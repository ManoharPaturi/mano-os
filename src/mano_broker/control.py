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
from .verifier import check, declare


def dispatch_control(state, packet, *, peer, now, boot_id, runtime=None):
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
    if value["operation"] == "declare_artifact_contract":
        if set(body) != {"approval_id", "path", "sha256", "size"}:
            raise Denied("Unexpected expectation fields")
        declare(state, body["approval_id"], path=body["path"], sha256=body["sha256"],
                size=body["size"], now=now, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True)
    if value["operation"] == "check_artifact_contract":
        if set(body) != {"action_id", "artifact_id"}:
            raise Denied("Unexpected verifier fields")
        result = check(state, body["action_id"], body["artifact_id"], boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, verification=result)
    if value["operation"] == "capture_artifact":
        if runtime is None or set(body) != {"action_id", "path"}:
            raise Denied("Trusted live artifact capture required")
        metadata = runtime.artifacts.capture(state, runtime.registry, body["action_id"],
                                             body["path"], boot_id=boot_id)
        artifact_id = metadata["artifact_id"]
        try:
            runtime.artifacts.persist(state, artifact_id)
        except BaseException:
            runtime.artifacts.items.pop(artifact_id).close()
            raise
        return dict(schema_version="1.0", ok=True, artifact=metadata)
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


def serve_control(state, connection, *, boot_id, runtime=None):
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)
        result = dispatch_control(state, packet, peer=peer, now=time.monotonic(),
                                  boot_id=boot_id, runtime=runtime)
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    payload = canonical(result).encode()
    if len(payload) > 131072:
        payload = canonical({"schema_version": "1.0", "ok": False, "error": "denied"}).encode()
    try:
        connection.sendall(payload)
    except OSError:
        pass
