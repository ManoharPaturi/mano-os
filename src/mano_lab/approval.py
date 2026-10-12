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
    def create(cls, now, expired=False):
        return cls(
            {
                "request_id": secrets.token_hex(16),
                "task_id": secrets.token_hex(16),
                "operation": "record_fixture_approval",
                "target": TARGET,
                "risk": "low; disposable CI marker only",
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
