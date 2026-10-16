"""Durable pending approvals. Confirmation is trusted-only, not a wire endpoint.

A future separate PAM channel must authenticate the human before calling approve.
Neither a model assertion nor this library method authenticates a person.
"""

import hashlib
import hmac
import json
import math
import secrets

from .protocol import ActionRequest, canonical, identifier
from .state import Denied


def clock(now):
    if type(now) not in {int, float} or not math.isfinite(now) or now < 0:
        raise ValueError("Expected trusted monotonic clock")


class Approvals:
    def __init__(self, state):
        self.state = state
        with state.transaction():
            state.db.execute("""CREATE TABLE IF NOT EXISTS approvals(
                id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(id),
                request_key TEXT NOT NULL,proposal_json TEXT NOT NULL,
                request_digest TEXT NOT NULL,view_json TEXT NOT NULL,
                state TEXT NOT NULL,grant_id TEXT REFERENCES grants(id),
                UNIQUE(task_id,request_key))""")

    def request(self, proposal, *, caller_uid, now, boot_id):
        clock(now)
        # A proposal has no grant yet; zero ID is a parser placeholder, not authority.
        if not isinstance(proposal, dict) or set(proposal) != {
            "schema_version",
            "task_id",
            "capability",
            "resource_id",
            "args",
            "idempotency_key",
            "reason",
        }:
            raise Denied("Unexpected approval proposal")
        request = ActionRequest.parse(canonical(proposal | {"grant_id": "0" * 32}).encode())
        with self.state.transaction():
            task = self.state.db.execute(
                "SELECT * FROM tasks WHERE id=?", (request.task_id,)
            ).fetchone()
            if (
                task is None
                or type(caller_uid) is not int
                or task["caller_uid"] != caller_uid
                or task["boot_id"] != boot_id
                or task["resource_id"] != request.resource_id
            ):
                raise Denied("Approval task identity/resource mismatch")
            prior = self.state.db.execute(
                "SELECT * FROM approvals WHERE task_id=? AND request_key=?",
                (request.task_id, request.idempotency_key),
            ).fetchone()
            if prior:
                if prior["request_digest"] != request.digest:
                    raise Denied("Approval idempotency conflict")
                return self.public(prior, now)
            if self.state.meta("latched"):
                raise Denied("Stop latched")
            # Lifetime quota, not just outstanding count: stale-request spam cannot
            # grow this trusted journal indefinitely under one task identity.
            count = self.state.db.execute(
                "SELECT count(*) FROM approvals WHERE task_id=?", (request.task_id,)
            ).fetchone()[0]
            if count >= 64:
                raise Denied("Task approval quota exhausted")
            approval_id = secrets.token_hex(16)
            view = {
                "schema_version": "1.0",
                "approval_id": approval_id,
                "task_id": task["id"],
                "human_uid": task["human_uid"],
                "capability": request.capability.value,
                "resource_id": request.resource_id,
                "args": json.loads(request.args_json),
                "classification": task["classification"],
                "reason_untrusted": request.reason,
                "nonce": secrets.token_hex(32),
                "expires": now + 60,
                "boot_id": boot_id,
                "epoch": self.state.meta("epoch"),
            }
            row = dict(id=approval_id, state="pending", grant_id=None, view_json=canonical(view))
            self.state.db.execute(
                "INSERT INTO approvals VALUES(?,?,?,?,?,?,'pending',NULL)",
                (
                    approval_id,
                    task["id"],
                    request.idempotency_key,
                    canonical(request.body()),
                    request.digest,
                    canonical(view),
                ),
            )
            self.state.event(
                None, "approval-requested", {"approval_id": approval_id, "task_id": task["id"]}
            )
            return self.public(row, now)

    def public(self, row, now):
        state = row["state"]
        if state == "pending":
            view = json.loads(row["view_json"])
            if self.state.meta("latched") or self.state.meta("epoch") != view["epoch"]:
                state = "revoked"
            elif now >= view["expires"]:
                state = "expired"
        return {"approval_id": row["id"], "state": state, "grant_id": row["grant_id"]}

    def status(self, approval_id, *, caller_uid, now, boot_id):
        clock(now)
        identifier(approval_id)
        row = self.state.db.execute(
            "SELECT a.* FROM approvals a JOIN tasks t ON a.task_id=t.id "
            "WHERE a.id=? AND t.caller_uid=? AND t.boot_id=?",
            (approval_id, caller_uid, boot_id),
        ).fetchone()
        if row is None or type(caller_uid) is not int:
            raise Denied("Approval unavailable")
        return self.public(row, now)

    def view(self, approval_id, *, human_uid):
        identifier(approval_id)
        row = self.state.db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if row is None or type(human_uid) is not int:
            raise Denied("Approval unavailable")
        view = json.loads(row["view_json"])
        if view["human_uid"] != human_uid:
            raise Denied("Wrong approval human")
        # Only the protected human/PAM channel may expose this view/nonce.
        return view | {"operation_digest": hashlib.sha256(canonical(view).encode()).hexdigest()}

    def approve(
        self, approval_id, *, authenticated_human_uid, nonce, operation_digest, now, boot_id
    ):
        """Trusted PAM adapter only. Atomically consume challenge and issue one grant."""
        clock(now)
        with self.state.transaction():
            row = self.state.db.execute(
                "SELECT * FROM approvals WHERE id=?", (identifier(approval_id),)
            ).fetchone()
            if row is None or row["state"] != "pending":
                raise Denied("Approval not pending")
            view = self.view(approval_id, human_uid=authenticated_human_uid)
            if (
                type(nonce) is not str
                or type(operation_digest) is not str
                or not nonce.isascii()
                or not operation_digest.isascii()
                or not hmac.compare_digest(nonce, view["nonce"])
                or not hmac.compare_digest(operation_digest, view["operation_digest"])
                or now >= view["expires"]
                or boot_id != view["boot_id"]
                or self.state.meta("latched")
                or self.state.meta("epoch") != view["epoch"]
            ):
                raise Denied("Approval binding expired or revoked")
            grant = self.state.issue_grant(
                view["task_id"],
                approved_human_uid=authenticated_human_uid,
                approved_args=view["args"],
                capability=view["capability"],
                resource_id=view["resource_id"],
                expires=view["expires"],
                max_count=1,
                memory_bytes=256 * 1024**2,
                pids=32,
                cpu_percent=20,
                max_timeout_seconds=300,
            )
            if view["capability"] == "model.set_budget":
                from .model_budget import ModelBudget

                ModelBudget(self.state).apply_grant(grant, now=now, boot_id=boot_id)
            self.state.db.execute(
                "UPDATE approvals SET state='approved',grant_id=? WHERE id=?", (grant, approval_id)
            )
            self.state.event(
                None, "approval-consumed", {"approval_id": approval_id, "grant_id": grant}
            )
            return grant
