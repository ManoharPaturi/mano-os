"""Explicit approved Git checkpoint requests and scoped immutable byte retrieval."""

import base64
import hashlib
import time

from mano_protocol.actions import ActionRequest, canonical, identifier
from mano_protocol.checkpoints import EXCLUDED, metadata


def proposal(*, task_id, resource_id, key, reason):
    value = dict(
        schema_version="1.0",
        task_id=task_id,
        resource_id=resource_id,
        capability="workspace.checkpoint",
        args=dict(root=".", excluded_names=list(EXCLUDED)),
        idempotency_key=key,
        reason=reason,
    )
    ActionRequest.parse(canonical(value | dict(grant_id="0" * 32)).encode())
    return value


class Checkpoint:
    def __init__(self, client, *, proposal, action_id):
        parsed = ActionRequest.parse(canonical(proposal | dict(grant_id="0" * 32)).encode())
        if parsed.capability != "workspace.checkpoint":
            raise ValueError("Exact checkpoint proposal required")
        self.client, self.task_id = client, parsed.task_id
        self.resource_id = parsed.resource_id
        self.action_id = identifier(action_id)
        self.digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()

    @staticmethod
    def request_approval(client, *, proposal):
        parsed = ActionRequest.parse(canonical(proposal | dict(grant_id="0" * 32)).encode())
        if parsed.capability != "workspace.checkpoint":
            raise ValueError("Expected checkpoint proposal")
        response = client(dict(schema_version="1.0", operation="request_approval", body=proposal))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("Checkpoint approval request denied")
        return response

    @classmethod
    def start(cls, client, *, proposal, grant_id):
        worker = cls(client, proposal=proposal, action_id="0" * 32)
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant_id)).encode())
        response = client(dict(schema_version="1.0", operation="propose", body=request.body()))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError(
                "Checkpoint submission denied or uncertain; never recapture automatically"
            )
        worker.action_id = identifier(response["action"]["id"])
        worker.bound(response["action"])
        return worker

    def bound(self, action):
        if (
            not isinstance(action, dict)
            or action.get("id") != self.action_id
            or action.get("task_id") != self.task_id
            or action.get("proposal_digest") != self.digest
            or action.get("verified") != 0
        ):
            raise ValueError("Checkpoint action changed")
        return action

    def query(self, operation, **args):
        response = self.client(
            dict(
                schema_version="1.0",
                operation=operation,
                body=dict(task_id=self.task_id, action_id=self.action_id, **args),
            )
        )
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("Checkpoint unavailable; reconcile without recapture")
        return response

    def status(self):
        return self.bound(self.query("status")["action"])

    def receipt(self):
        if self.status()["state"] != "done":
            raise ValueError("No durable completed checkpoint")
        value = metadata(self.query("checkpoint_result")["checkpoint"])
        if value["action_id"] != self.action_id or value["task_id"] != self.task_id:
            raise ValueError("Checkpoint receipt scope changed")
        return value

    def read(self):
        receipt = self.receipt()
        data = bytearray()
        while len(data) < receipt["archive_bytes"]:
            time.sleep(0.11)  # Respect the broker's global public request rate.
            response = self.query("checkpoint_read", offset=len(data), length=16384)
            if metadata(response["checkpoint"]) != receipt or type(response.get("eof")) is not bool:
                raise ValueError("Checkpoint receipt changed during retrieval")
            piece = base64.b64decode(response["data"], validate=True)
            if len(piece) != min(16384, receipt["archive_bytes"] - len(data)) or response[
                "eof"
            ] != (len(data) + len(piece) == receipt["archive_bytes"]):
                raise ValueError("Checkpoint bytes incomplete or changed")
            data.extend(piece)
        if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
            raise ValueError("Checkpoint archive integrity mismatch")
        return dict(metadata=receipt, data=bytes(data))
