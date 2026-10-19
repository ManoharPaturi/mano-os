"""Trusted process-local resource registry and prepared action descriptors.

No root paths/provisioning FDs are accepted from public IPC; provisioning and execution are
separate trusted adapters. Handles cannot be restored from model-selected paths.
"""

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .protocol import ActionRequest, Capability, canonical, identifier
from .resources import Pinned, Workspace
from .state import Denied


@dataclass
class Resource:
    workspace: Workspace
    human_uid: int
    caller_uid: int
    boot_id: str
    task_id: str | None = None


@dataclass
class Prepared:
    action_id: str
    resource_id: str
    descriptors: dict[str, Pinned] = field(default_factory=dict)
    create_name: str | None = None
    started: bool = False
    closed: bool = False

    def close(self):
        for descriptor in self.descriptors.values():
            descriptor.close()
        self.closed = True


class Registry:
    def __init__(self, *, model_policy=None):
        self.model_policy = model_policy
        self.resources = {}
        self.leases = {}
        self.closed = False

    def register(self, trusted_directory_fd, *, human_uid, caller_uid, boot_id):
        if (
            self.closed
            or len(self.resources) >= 32
            or type(human_uid) is not int
            or human_uid < 0
            or type(caller_uid) is not int
            or caller_uid <= 0
            or caller_uid in {human_uid, os.geteuid()}
            or not isinstance(boot_id, str)
            or not boot_id
        ):
            raise Denied("Invalid trusted resource provisioning or quota")
        workspace = Workspace(trusted_directory_fd)
        resource_id = secrets.token_hex(16)
        self.resources[resource_id] = Resource(workspace, human_uid, caller_uid, boot_id)
        return resource_id

    def prepare(self, state, request, *, caller_uid, now, boot_id):
        request = ActionRequest.parse(canonical(request.body()).encode())
        if request.capability in {Capability.BUDGET, Capability.PROFILE}:
            raise Denied('Task budgets and profiles change only through authenticated approval')
        if request.capability == Capability.PLAN:
            if self.model_policy is None:
                raise Denied('Protected provider executor is not installed')
            self.model_policy(json.loads(request.args_json))
        resource = self.resources.get(request.resource_id)
        task = state.db.execute("SELECT * FROM tasks WHERE id=?", (request.task_id,)).fetchone()
        if (
            self.closed
            or resource is None
            or task is None
            or type(caller_uid) is not int
            or task["resource_id"] != request.resource_id
            or task["caller_uid"] != caller_uid
            or (resource.human_uid, resource.caller_uid, resource.boot_id)
            != (task["human_uid"], caller_uid, boot_id)
            or task["boot_id"] != boot_id
            or (resource.task_id is not None and resource.task_id != request.task_id)
        ):
            raise Denied("No live resource authority for this task/caller/boot")
        with state.transaction():
            row, fresh = state.authorize(request, caller_uid=caller_uid, now=now, boot_id=boot_id)
            if fresh and len(self.leases) >= 32:
                raise Denied("Prepared descriptor quota exhausted")
        resource.task_id = request.task_id
        if not fresh:
            return row, None
        prepared = Prepared(row["id"], request.resource_id)
        args = json.loads(request.args_json)
        try:
            if request.capability == Capability.READ:
                prepared.descriptors["target"] = resource.workspace.pin(args["path"])
            elif request.capability == Capability.WRITE:
                path = PurePosixPath(args["path"])
                # A future writer must use this parent FD and O_EXCL for creation,
                # or the pinned existing inode, never re-resolve the submitted path.
                prepared.descriptors["parent"] = resource.workspace.pin(
                    str(path.parent), directory=True
                )
                try:
                    with Workspace(prepared.descriptors["parent"].fd) as parent:
                        prepared.descriptors["target"] = parent.pin(path.name)
                except FileNotFoundError:
                    prepared.create_name = path.name
            elif request.capability in {Capability.RUN, Capability.PTY}:
                prepared.descriptors["cwd"] = resource.workspace.pin(args["cwd"], directory=True)
            self.leases[row["id"]] = prepared
            return row, prepared
        except BaseException:
            prepared.close()
            # Preserve failed intent/use; never silently repeat a partly prepared action.
            current = state.db.execute(
                "SELECT state FROM actions WHERE id=?", (row["id"],)
            ).fetchone()
            if current["state"] == "intent":
                state.transition(row["id"], "failed")
            raise

    def start(self, state, action_id, *, now, boot_id):
        identifier(action_id)
        prepared = self.leases.get(action_id)
        if self.closed or prepared is None or prepared.closed or prepared.started:
            raise Denied("No unclaimed live descriptor lease")
        try:
            state.start(action_id, now=now, boot_id=boot_id)
        except BaseException:
            self.release(action_id)
            raise
        prepared.started = True
        return prepared  # Trusted executor only; this does not execute anything.

    def release(self, action_id):
        prepared = self.leases.pop(action_id, None)
        if prepared:
            prepared.close()

    def close(self):
        for prepared in self.leases.values():
            prepared.close()
        for resource in self.resources.values():
            resource.workspace.close()
        self.leases.clear()
        self.resources.clear()
        self.closed = True
