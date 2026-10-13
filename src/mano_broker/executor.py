"""Trusted terminal adapter: durable intent/start before private effects.

No public execution endpoint. Runtime integration and independent native Stop
remain separate gates. A lost response is never automatically retried.
"""

import json
import time

from .protocol import ActionRequest, Capability, canonical, identifier
from .state import Denied


class Executor:
    def __init__(self, state, registry, client, *, boot_id, clock=time.monotonic):
        self.state, self.registry, self.client = state, registry, client
        self.boot_id, self.clock = boot_id, clock
        self.jobs = {}

    def authority(self, action_id, expected):
        row = self.state.db.execute(
            "SELECT a.*,g.revoked,g.epoch,g.expires,g.approved_args_json,g.budget_json,"
            "t.boot_id,t.caller_uid FROM actions a JOIN grants g ON a.grant_id=g.id "
            "JOIN tasks t ON a.task_id=t.id WHERE a.id=?", (action_id,)
        ).fetchone()
        if row is None:
            raise Denied("Unknown terminal action")
        request = ActionRequest.parse(row["request_json"].encode())
        if (
            row["state"] != expected or row["revoked"] or self.state.meta("latched")
            or row["epoch"] != self.state.meta("epoch") or self.clock() >= row["expires"]
            or row["boot_id"] != self.boot_id or request.capability != Capability.RUN
            or canonical(json.loads(request.args_json)) != row["approved_args_json"]
        ):
            raise Denied("Terminal authority no longer live")
        # The current delegated launcher uses these fixed ceilings. Do not run
        # a smaller approved budget under a larger kernel limit.
        budget = json.loads(row["budget_json"])
        if (budget["memory_bytes"] < 128 * 1024**2 or budget["pids"] < 24
                or budget["cpu_percent"] < 20):
            raise Denied("Approved budget below current launcher ceilings")
        return row, request

    def control(self, operation, handle):
        response = self.client.exchange("control", dict(
            schema_version="1.0", operation=operation, body=handle
        ))
        if (response.get("ok") is not True or any(response.get(k) != v
                for k, v in handle.items()) or response.get("effect_verified") is not False):
            raise Denied("Unbound private lifecycle response")
        return response

    def settle_unknown(self, action_id):
        row = self.state.db.execute("SELECT state FROM actions WHERE id=?", (action_id,)).fetchone()
        if row and row[0] == "executing":
            self.state.transition(action_id, "unknown")
        elif row and row[0] == "intent":
            self.state.transition(action_id, "failed")

    def launch(self, action_id):
        identifier(action_id)
        if action_id in self.jobs:
            raise Denied("Action already submitted")
        handle = None
        try:
            row, request = self.authority(action_id, "intent")
            prepared = self.registry.leases.get(action_id)
            resource = self.registry.resources.get(request.resource_id)
            if (prepared is None or prepared.closed or prepared.started or resource is None
                    or prepared.resource_id != request.resource_id
                    or resource.task_id != request.task_id
                    or resource.caller_uid != row["caller_uid"]
                    or resource.boot_id != self.boot_id
                    or set(prepared.descriptors) != {"cwd"}):
                raise Denied("Live terminal descriptor lease required")
            response = self.client.exchange("prepare", dict(
                schema_version="1.0", operation="launch_task", body=dict(
                    action_id=action_id, caller_uid=row["caller_uid"], request=request.body()
                )
            ), (resource.workspace.fd, prepared.descriptors["cwd"].fd))
            if (response.get("ok") is not True or response.get("action_id") != action_id
                    or response.get("state") != "prepared"):
                raise Denied("Launcher did not prepare this action")
            handle = {key: identifier(response[key])
                      for key in ("instance_id", "job_id", "action_id")}
            # Recheck after the blocking prepare round trip. State.start commits
            # executing durably before any start packet can leave this process.
            self.authority(action_id, "intent")
            self.registry.start(self.state, action_id, now=self.clock(), boot_id=self.boot_id)
            self.jobs[action_id] = handle
            response = self.control("start", handle)
            if response.get("state") not in {"running", "finished"}:
                raise Denied("Uncertain start acknowledgement")
            return response
        except BaseException:
            if handle is not None:
                try:
                    self.control("cancel", handle)
                except (OSError, ValueError, KeyError, TypeError):
                    pass
            self.settle_unknown(action_id)
            self.jobs.pop(action_id, None)
            raise
        finally:
            self.registry.release(action_id)

    def poll(self, action_id):
        identifier(action_id)
        handle = self.jobs[action_id]
        try:
            self.authority(action_id, "executing")
            response = self.control("status", handle)
            status = response.get("state")
            if status == "running":
                return response
            if status != "finished" or type(response.get("return_code")) is not int:
                raise Denied("No explicit completed exit outcome")
            code = response["return_code"]
            self.state.transition(action_id, "done" if code == 0 else "failed", exit_code=code)
            self.jobs.pop(action_id)
            return response
        except BaseException:
            try:
                self.control("cancel", handle)
            except (OSError, ValueError, KeyError, TypeError):
                pass
            self.settle_unknown(action_id)
            self.jobs.pop(action_id, None)
            raise
