"""Root-only confirmation channel for the separate trusted PAM adapter.

Root confirmation is trusted OS authority, not evidence that PAM has run. The
adapter must authenticate the human before confirming; no public caller can do so.
"""

import json
import time

from .approvals import Approvals
from .ipc import receive
from .protocol import canonical, unique_object
from .state import Denied


def dispatch_control(state, packet, *, peer, now, boot_id):
    if peer.uid != 0:
        raise Denied("Control requires trusted root adapter")
    value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "operation", "body"}
        or value["schema_version"] != "1.0"
        or not isinstance(value["body"], dict)
    ):
        raise Denied("Unexpected control envelope")
    body = value["body"]
    queue = Approvals(state)
    if value["operation"] == "approval_view":
        if set(body) != {"approval_id", "human_uid"}:
            raise Denied("Unexpected view fields")
        return {
            "schema_version": "1.0",
            "ok": True,
            "view": queue.view(body["approval_id"], human_uid=body["human_uid"]),
        }
    if value["operation"] == "confirm_approval":
        if set(body) != {"approval_id", "human_uid", "nonce", "operation_digest"}:
            raise Denied("Unexpected confirmation fields")
        grant = queue.approve(
            body["approval_id"],
            authenticated_human_uid=body["human_uid"],
            nonce=body["nonce"],
            operation_digest=body["operation_digest"],
            now=now,
            boot_id=boot_id,
        )
        return {"schema_version": "1.0", "ok": True, "grant_id": grant}
    raise Denied("Control operation not supported")


def serve_control(state, connection, *, boot_id):
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)
        result = dispatch_control(state, packet, peer=peer, now=time.monotonic(), boot_id=boot_id)
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    payload = canonical(result).encode()
    if len(payload) > 131072:
        payload = canonical({"schema_version": "1.0", "ok": False, "error": "denied"}).encode()
    try:
        connection.sendall(payload)
    except OSError:
        pass
