"""Explicit human-approved local MCP discovery; metadata never authorizes tools."""

import hashlib
import json

from mano_protocol.actions import ActionRequest, canonical, identifier, unique_object
from mano_protocol.mcp import VERSION, decode, manifest

from .broker import read_terminal_output


def proposal(*, task_id, resource_id, argv, key, reason, cwd=".", timeout_seconds=20):
    value = dict(schema_version="1.0", task_id=task_id, resource_id=resource_id,
                 capability="mcp.discover", args=dict(argv=argv, cwd=cwd,
                 timeout_seconds=timeout_seconds, protocol_version=VERSION),
                 idempotency_key=key, reason=reason)
    ActionRequest.parse(canonical(value | dict(grant_id="0" * 32)).encode())
    return value


class MCPDiscovery:
    def __init__(self, client, *, request, action_id):
        if request.capability != "mcp.discover":
            raise ValueError("Approved MCP discovery required")
        self.client, self.request = client, request
        self.action_id = identifier(action_id)
        value = request.body()
        del value["grant_id"]
        self.digest = hashlib.sha256(canonical(value).encode()).hexdigest()

    @staticmethod
    def request_approval(client, *, proposal):
        request = ActionRequest.parse(canonical(proposal | dict(grant_id="0" * 32)).encode())
        if request.capability != "mcp.discover":
            raise ValueError("Expected MCP proposal")
        result = client(dict(schema_version="1.0", operation="request_approval", body=proposal))
        if result.get("ok") is not True:
            raise ValueError("MCP discovery approval denied")
        return result

    @classmethod
    def start(cls, client, *, proposal, grant_id):
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant_id)).encode())
        if request.capability != "mcp.discover":
            raise ValueError("Expected MCP proposal")
        response = client(dict(schema_version="1.0", operation="propose", body=request.body()))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("MCP start denied or uncertain; do not restart")
        worker = cls(client, request=request, action_id=response["action"]["id"])
        worker.bound(response["action"])
        return worker

    def bound(self, action):
        if (not isinstance(action, dict) or action.get("id") != self.action_id
                or action.get("task_id") != self.request.task_id
                or action.get("proposal_digest") != self.digest
                or action.get("verified") != 0):
            raise ValueError("MCP action identity or approval changed")
        return action

    def status(self):
        response = self.client(dict(schema_version="1.0", operation="status",
            body=dict(task_id=self.request.task_id, action_id=self.action_id)))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError("MCP status unavailable; reconcile without restart")
        return self.bound(response["action"])

    def result(self):
        action = self.status()
        if action["state"] not in {"done", "failed"}:
            raise ValueError("MCP operation has no durable completed capture")
        capture = read_terminal_output(self.client, task_id=self.request.task_id,
                                       action_id=self.action_id)
        meta = capture["metadata"]
        if (meta["return_code"] != action["exit_code"]
                or (action["state"] == "done") != (meta["return_code"] == 0)):
            raise ValueError("MCP capture differs from journal")
        value = None
        if action["state"] == "done":
            # A complete manifest can exceed a single wire line's 32 KiB budget.
            value = manifest(json.loads(capture["stdout"], object_pairs_hook=unique_object))
        elif capture["stdout"]:
            value = decode(capture["stdout"])
        return dict(status="discovered" if action["state"] == "done" else "failed",
                    manifest=value if action["state"] == "done" else None,
                    failure=value if action["state"] == "failed" else None,
                    metadata=meta, stderr=capture["stderr"], untrusted=True,
                    effect_verified=False, invocation_authorized=False)
