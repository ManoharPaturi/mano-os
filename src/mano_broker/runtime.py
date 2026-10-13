"""Broker request facade coupled to live resource descriptors; no executor."""

import json
import time

from .ipc import dispatch, public_action, receive
from .protocol import ActionRequest, canonical, identifier, unique_object
from .registry import Registry
from .state import Denied


class Runtime:
    def __init__(self, state, *, boot_id):
        self.state = state
        self.boot_id = boot_id
        self.registry = Registry()
        # Process-local FD authority cannot survive daemon restart. Keep history,
        # reconcile executing state and revoke old intent/grant/pending epoch.
        with state.transaction():
            state.recover()
            state.db.execute("UPDATE grants SET revoked=1")
            state.db.execute("UPDATE actions SET state='failed' WHERE state='intent'")
            state.db.execute("UPDATE meta SET value=value+1 WHERE key='epoch'")
            state.event(None, "runtime-authority-renewal", {"epoch": state.meta("epoch")})

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
            request = ActionRequest.parse(canonical(value["body"]).encode())
            row, prepared = self.registry.prepare(
                self.state, request, caller_uid=peer.uid, now=now, boot_id=self.boot_id
            )
            return {
                "schema_version": "1.0",
                "ok": True,
                "fresh": prepared is not None,
                "action": public_action(row),
            }
        return dispatch(self.state, packet, peer=peer, now=now, boot_id=self.boot_id)

    def close(self):
        self.registry.close()


def serve_runtime(runtime, connection):
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)
        result = runtime.dispatch(packet, peer=peer, now=time.monotonic())
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    try:
        connection.sendall(canonical(result).encode())
    except OSError:
        pass
