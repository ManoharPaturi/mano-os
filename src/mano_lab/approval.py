"""Disposable approval spike only. No model-facing or arbitrary execution API."""

import hashlib
import json
import secrets
from dataclasses import dataclass

TARGET = "/var/lib/mano-broker/approval-fixture"


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass
class Request:
    view: dict
    consumed: bool = False

    @classmethod
    def create(cls, now, expired=False, rearm=False):
        return cls(
            {
                "request_id": secrets.token_hex(16),
                "task_id": secrets.token_hex(16),
                "operation": "rearm_fixture_session" if rearm else "authorize_fixture_session",
                "scope": ["fixed-marker", "CI-agent-input", "grant-check"],
                "target": TARGET,
                "risk": "low; fixed CI marker and isolated agent input only",
                "nonce": secrets.token_hex(32),
                "expires_at_monotonic": now - 1 if expired else now + 90,
            }
        )

    def decision(self, uid, human_uid, body, clock, authenticate):
        if uid != human_uid:
            return "peer-denied"
        if set(body) != {"action", "request_id", "nonce", "operation_digest", "password"}:
            return "schema-denied"
        if self.consumed:
            return "replay-denied"
        if clock() >= self.view["expires_at_monotonic"]:
            return "expired-denied"
        if (
            body["action"] != "approve"
            or body["request_id"] != self.view["request_id"]
            or body["nonce"] != self.view["nonce"]
            or body["operation_digest"] != digest(self.view)
        ):
            return "binding-denied"
        password = body["password"]
        if (
            not isinstance(password, str)
            or not 1 <= len(password) <= 256
            or "\x00" in password
            or "\n" in password
        ):
            return "auth-denied"
        if not authenticate(password):
            return "auth-denied"
        if clock() >= self.view["expires_at_monotonic"]:
            return "expired-denied"
        self.consumed = True
        return "approved"


def grant_decision(request, body, issued_epoch, current_epoch, latched, clock):
    if set(body) != {"action", "request_id", "nonce", "operation_digest"}:
        return "schema-denied"
    if latched or issued_epoch != current_epoch:
        return "revoked-denied"
    if not request.consumed:
        return "grant-denied"
    if clock() >= request.view["expires_at_monotonic"]:
        return "expired-denied"
    if (
        body["action"] != "use_grant"
        or body["request_id"] != request.view["request_id"]
        or body["nonce"] != request.view["nonce"]
        or body["operation_digest"] != digest(request.view)
    ):
        return "binding-denied"
    return "grant-valid"
