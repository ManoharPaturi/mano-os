"""Explicit approval/open and bounded interactive PTY SDK; no effect retries."""

import base64
import hashlib

from mano_protocol.actions import ActionRequest, canonical, identifier


class PTYSession:
    def __init__(self, client, *, task_id, action_id):
        self.client = client
        self.task_id, self.action_id = identifier(task_id), identifier(action_id)
        self.output = bytearray()

    @staticmethod
    def request(
        client,
        *,
        task_id,
        resource_id,
        argv,
        key,
        reason,
        cwd=".",
        timeout_seconds=30,
        rows=24,
        columns=80,
        input_limit_bytes=65536,
    ):
        proposal = dict(
            schema_version="1.0",
            task_id=task_id,
            resource_id=resource_id,
            capability="terminal.open_pty",
            args=dict(
                argv=argv,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                rows=rows,
                columns=columns,
                input_limit_bytes=input_limit_bytes,
            ),
            idempotency_key=key,
            reason=reason,
        )
        ActionRequest.parse(canonical(proposal | dict(grant_id="0" * 32)).encode())
        response = client(dict(schema_version="1.0", operation="request_approval", body=proposal))
        if response.get("ok") is not True:
            raise ValueError("PTY approval request denied")
        return response  # Human authenticates through the separate native PAM path.

    @classmethod
    def open(cls, client, *, proposal, grant_id):
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant_id)).encode())
        if request.capability != "terminal.open_pty":
            raise ValueError("Expected approved PTY proposal")
        response = client(dict(schema_version="1.0", operation="propose", body=request.body()))
        if response.get("ok") is not True:
            raise ValueError("PTY open denied")
        return cls(client, task_id=request.task_id, action_id=response["action"]["id"])

    def exchange(self, operation, **args):
        response = self.client(
            dict(
                schema_version="1.0",
                operation=operation,
                body=dict(task_id=self.task_id, action_id=self.action_id, **args),
            )
        )
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("PTY request denied or uncertain; do not resend input")
        return response

    def status(self):
        return self.exchange("pty_status")["session"]

    def read(self):
        result = self.exchange("pty_read", offset=len(self.output), length=4096)["session"]
        data = base64.b64decode(result["data"], validate=True)
        if (
            result["offset"] != len(self.output)
            or len(data) > 4096
            or type(result["output_bytes"]) is not int
            or not len(self.output) + len(data) <= result["output_bytes"] <= 65536
            or type(result["eof"]) is not bool
            or hashlib.sha256(self.output + data).hexdigest() != result["prefix_sha256"]
        ):
            raise ValueError("PTY output identity or bounds changed")
        self.output.extend(data)
        return dict(data=data, eof=result["eof"], state=result["state"], outcome=result["outcome"])

    def write(self, data, *, key):
        if not isinstance(data, bytes) or not 1 <= len(data) <= 4096:
            raise ValueError("PTY writes require 1..4096 bytes")
        return self.exchange("pty_write", key=key, data=base64.b64encode(data).decode("ascii"))[
            "operation"
        ]

    def resize(self, rows, columns, *, key):
        return self.exchange("pty_resize", key=key, rows=rows, columns=columns)["operation"]

    def close(self, *, key):
        return self.exchange("pty_close", key=key)["operation"]
