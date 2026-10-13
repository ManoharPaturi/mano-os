"""Broker request facade, descriptor custody and trusted terminal scheduling."""

import json
import sys
import time
from collections import deque

from .executor import Executor
from .ipc import dispatch, public_action, receive
from .protocol import ActionRequest, Capability, canonical, identifier, unique_object
from .registry import Registry
from .state import Denied
from .stop_state import latched


class Runtime:
    def __init__(self, state, *, boot_id, launcher=None, stop_reader=None):
        self.state = state
        self.boot_id = boot_id
        self.registry = Registry()
        self.pending = deque()
        self.launcher = launcher
        self.stop_reader = stop_reader or (latched if launcher else None)
        self.executor = (
            Executor(state, self.registry, launcher, boot_id=boot_id) if launcher else None
        )
        # Process-local FD authority cannot survive daemon restart. Keep history,
        # reconcile executing state and revoke old intent/grant/pending epoch.
        with state.transaction():
            state.recover()
            state.db.execute("UPDATE grants SET revoked=1")
            state.db.execute("UPDATE actions SET state='failed' WHERE state='intent'")
            state.db.execute("UPDATE meta SET value=value+1 WHERE key='epoch'")
            state.event(None, "runtime-authority-renewal", {"epoch": state.meta("epoch")})
        self.sync_stop()

    def sync_stop(self):
        if self.stop_reader is None:
            return
        try:
            stopped = self.stop_reader()
            if type(stopped) is not bool:
                stopped = True
        except (OSError, ValueError):
            stopped = True  # Missing/corrupt authority cannot enable execution.
        if stopped and not self.state.meta("latched"):
            self.state.emergency_stop()

    def live_task(self, body, peer):
        if not isinstance(body, dict):
            raise Denied("Expected task operation")
        task_id = identifier(body.get("task_id"))
        resource_id = identifier(body.get("resource_id"))
        task = self.state.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        resource = self.registry.resources.get(resource_id)
        if (
            task is None
            or resource is None
            or task["resource_id"] != resource_id
            or task["caller_uid"] != peer.uid
            or task["boot_id"] != self.boot_id
            or resource.task_id != task_id
            or (resource.human_uid, resource.caller_uid, resource.boot_id)
            != (task["human_uid"], peer.uid, self.boot_id)
        ):
            raise Denied("No live provisioned task")

    def dispatch(self, packet, *, peer, now):
        self.sync_stop()
        value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "operation", "body"}
            or value["schema_version"] != "1.0"
        ):
            raise Denied("Invalid runtime envelope")
        if value["operation"] in {"propose", "request_approval"}:
            self.live_task(value["body"], peer)
        if value["operation"] == "propose":
            if self.state.meta("latched"):
                raise Denied("Proposals unavailable while emergency Stop is latched")
            request = ActionRequest.parse(canonical(value["body"]).encode())
            row, prepared = self.registry.prepare(
                self.state, request, caller_uid=peer.uid, now=now, boot_id=self.boot_id
            )
            if prepared is not None and request.capability == Capability.RUN and self.executor:
                self.pending.append(row["id"])
            return {
                "schema_version": "1.0",
                "ok": True,
                "fresh": prepared is not None,
                "action": public_action(row),
            }
        return dispatch(self.state, packet, peer=peer, now=now, boot_id=self.boot_id)

    def tick(self):
        self.sync_stop()
        if self.executor is None:
            return
        for action_id in list(self.executor.jobs):
            try:
                self.executor.poll(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, "terminal-poll-denied", {
                    "error_type": type(error).__name__, "errno": getattr(error, "errno", None)
                })  # No arguments, paths, grants or secrets in diagnostics.
        if self.pending and len(self.executor.jobs) < 2:
            action_id = self.pending.popleft()
            try:
                self.executor.launch(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, "terminal-dispatch-denied", {
                    "error_type": type(error).__name__, "errno": getattr(error, "errno", None)
                })  # Failed/unknown intent is durable; never reschedule it.

    def close(self):
        try:
            if self.executor:
                for action_id, handle in list(self.executor.jobs.items()):
                    try:
                        self.executor.control("cancel", handle)
                    except (OSError, ValueError, KeyError, TypeError):
                        pass
                    self.executor.settle_unknown(action_id)
                for action_id in self.pending:
                    self.executor.settle_unknown(action_id)
                self.executor.jobs.clear()
            self.pending.clear()
        finally:
            self.registry.close()
            if self.launcher:
                self.launcher.close()


def serve_runtime(runtime, connection):
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)
        result = runtime.dispatch(packet, peer=peer, now=time.monotonic())
    except (ValueError, TypeError, KeyError, RecursionError, OSError) as error:
        print(
            canonical(
                {
                    "event": "runtime-request-denied",
                    "error_type": type(error).__name__,
                    "errno": getattr(error, "errno", None),
                }
            ),
            file=sys.stderr,
            flush=True,
        )
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    try:
        connection.sendall(canonical(result).encode())
    except OSError:
        pass
