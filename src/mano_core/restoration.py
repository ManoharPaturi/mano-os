"""Explicit source restoration; never guess or automatically replay an uncertain effect."""

import hashlib
import re

from mano_protocol.actions import ActionRequest, canonical, identifier


def proposal(*, before, source_action_id, source_sha256, key, reason):
    receipt = before.receipt()
    observed = before.query("checkpoint_layout")
    if observed.get("checkpoint") != receipt or not re.fullmatch(
        "[a-f0-9]{64}", observed.get("layout_sha256", "")
    ):
        raise ValueError("Fresh before checkpoint layout required")
    value = dict(
        schema_version="1.0",
        task_id=before.task_id,
        resource_id=before.resource_id,
        capability="workspace.restore",
        args=dict(
            source_action_id=source_action_id,
            source_sha256=source_sha256,
            before_action_id=before.action_id,
            before_sha256=receipt["sha256"],
            before_layout_sha256=observed["layout_sha256"],
        ),
        idempotency_key=key,
        reason=reason,
    )
    ActionRequest.parse(canonical(value | dict(grant_id="0" * 32)).encode())
    return value


class Restore:
    def __init__(self, client, *, proposal, action_id):
        parsed = ActionRequest.parse(canonical(proposal | dict(grant_id="0" * 32)).encode())
        if parsed.capability != "workspace.restore":
            raise ValueError("Exact restoration proposal required")
        self.client, self.task_id = client, parsed.task_id
        self.action_id = identifier(action_id)
        self.digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
        self.args = proposal["args"]

    @staticmethod
    def request_approval(client, *, proposal):
        parsed = ActionRequest.parse(canonical(proposal | dict(grant_id="0" * 32)).encode())
        if parsed.capability != "workspace.restore":
            raise ValueError("Expected source restore proposal")
        response = client(dict(schema_version="1.0", operation="request_approval", body=proposal))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("Restore approval request denied")
        return response

    @classmethod
    def start(cls, client, *, proposal, grant_id):
        worker = cls(client, proposal=proposal, action_id="0" * 32)
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant_id)).encode())
        response = client(dict(schema_version="1.0", operation="propose", body=request.body()))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("Restore denied or uncertain; do not resubmit automatically")
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
            raise ValueError("Restore action identity changed")
        return action

    def query(self, operation):
        response = self.client(
            dict(
                schema_version="1.0",
                operation=operation,
                body=dict(task_id=self.task_id, action_id=self.action_id),
            )
        )
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("Restore observation unavailable; reconcile without replay")
        return response

    def status(self):
        return self.bound(self.query("status")["action"])

    def result(self):
        action = self.status()
        observed = self.query("restore_result")["restore"]
        if (
            observed.get("state") != action["state"]
            or observed.get("automatic_retry_authorized") is not False
        ):
            raise ValueError("Restore result changed")
        steps = observed.get("steps")
        total = observed.get("total_steps")
        if (
            not isinstance(steps, list)
            or len(steps) > 192
            or (total is not None and (type(total) is not int or not 0 <= total <= 192))
        ):
            raise ValueError("Restore journal bounds changed")
        for index, item in enumerate(steps):
            if (
                not isinstance(item, dict)
                or set(item) != {"sequence", "state"}
                or type(item["sequence"]) is not int
                or item["sequence"] != index
                or item["state"] not in {"intent", "done", "unknown"}
            ):
                raise ValueError("Invalid restore step journal")
        receipt = observed.get("receipt")
        if action["state"] == "done":
            if (
                action.get("exit_code") != 0
                or total != len(steps)
                or any(item["state"] != "done" for item in steps)
            ):
                raise ValueError("Restore success lacks complete acknowledged steps")
            if (
                not isinstance(receipt, dict)
                or receipt.get("action_id") != self.action_id
                or receipt.get("source_sha256") != self.args["source_sha256"]
                or receipt.get("before_sha256") != self.args["before_sha256"]
                or receipt.get("postcondition_verified") is not True
                or receipt.get("current_content_verified") is not False
                or receipt.get("effect_verified") is not False
                or receipt.get("atomic_filesystem_restore") is not False
            ):
                raise ValueError("No bound successful restoration receipt")
        elif receipt is not None:
            raise ValueError("Unfinished restore cannot have a success receipt")
        return observed
