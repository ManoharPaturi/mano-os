"""Root-only confirmation channel for the separate trusted PAM adapter.

Root confirmation is trusted OS authority, not evidence that PAM has run. The
adapter must authenticate the human before confirming; no public caller can do so.
"""

import json
import time

from .approvals import Approvals
from .core_cycles import CoreCycles
from .human_status import snapshot as human_snapshot
from .ipc import public_action, receive
from .prompts import Prompts
from .protocol import canonical, identifier, unique_object
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
    if value['operation'] == 'inspect_file_read':
        from .file_reads import result_chunk

        if set(body) != {'task_id', 'action_id'}:
            raise Denied('Unexpected protected file read query')
        identifier(body['task_id'])
        identifier(body['action_id'])
        task = state.db.execute('SELECT caller_uid FROM tasks WHERE id=? AND boot_id=?',
                                (body['task_id'], boot_id)).fetchone()
        if task is None:
            raise Denied('Unknown current-boot task')
        result = result_chunk(state, **body, caller_uid=task['caller_uid'], boot_id=boot_id,
                              offset=0, length=1)
        return dict(schema_version='1.0', ok=True, artifact=result['metadata'])
    if value["operation"] == "claim_core_cycle":
        if set(body) != {"human_uid", "model", "max_output_tokens"}:
            raise Denied("Unexpected core cycle claim")
        cycle = CoreCycles(state).claim(**body, now=now, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, cycle=cycle)
    if value["operation"] == "finish_core_cycle":
        if set(body) != {"human_uid", "prompt_id", "nonce", "status"}:
            raise Denied("Unexpected core cycle result")
        CoreCycles(state).finish(**body, now=now, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True)
    if value["operation"] == "inspect_action":
        if set(body) != {"task_id", "action_id"}:
            raise Denied("Unexpected protected action query")
        identifier(body["task_id"])
        identifier(body["action_id"])
        row = state.db.execute("SELECT a.* FROM actions a JOIN tasks t ON a.task_id=t.id "
                               "WHERE a.id=? AND a.task_id=? AND t.boot_id=?",
                               (body["action_id"], body["task_id"], boot_id)).fetchone()
        if row is None:
            raise Denied("No matching journal action")
        return dict(schema_version="1.0", ok=True, action=public_action(row))
    if value["operation"] == "submit_prompt":
        if set(body) != {"human_uid", "request_key", "prompt"}:
            raise Denied("Unexpected human prompt fields")
        result = Prompts(state).submit(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, prompt=result)
    if value["operation"] == "pending_prompts":
        if set(body) != {"human_uid"}:
            raise Denied("Unexpected prompt discovery fields")
        prompts = Prompts(state).pending(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, prompts=prompts)
    if value['operation'] == 'permission_status':
        if set(body) != {'human_uid', 'prompt_id'}:
            raise Denied('Unexpected human permission query fields')
        from .human_profiles import profile_status

        return dict(schema_version='1.0', ok=True,
                    **profile_status(state, **body, now=now, boot_id=boot_id))
    if value['operation'] == 'request_profile':
        if set(body) != {'human_uid', 'prompt_id', 'request_key', 'args'}:
            raise Denied('Unexpected human profile fields')
        from .human_profiles import request_profile

        return dict(schema_version='1.0', ok=True,
                    **request_profile(state, **body, now=now, boot_id=boot_id, runtime=runtime))
    if value["operation"] == "human_task_status":
        if set(body) != {"human_uid", "prompt_id"}:
            raise Denied("Unexpected human task status fields")
        result = human_snapshot(state, **body, now=now, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, snapshot=result)
    if value["operation"] == "prompt_status":
        if set(body) != {"human_uid", "prompt_id"}:
            raise Denied("Unexpected prompt status fields")
        result = Prompts(state).status(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, prompt=result)
    if value["operation"] == "claim_prompt":
        if set(body) != {"human_uid", "prompt_id"}:
            raise Denied("Unexpected prompt claim fields")
        result = Prompts(state).claim(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, prompt=result)
    if value["operation"] == "attach_prompt_task":
        if set(body) != {"human_uid", "prompt_id", "task_id"}:
            raise Denied("Unexpected prompt attachment fields")
        result = Prompts(state).attach(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, prompt=result)
    if value["operation"] == "uncertain_prompt_creation":
        if set(body) != {"human_uid", "prompt_id"}:
            raise Denied("Unexpected uncertain prompt fields")
        result = Prompts(state).uncertain(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, prompt=result)
    if value["operation"] == "store_prompt_context":
        if set(body) != {"human_uid", "prompt_id", "managed"}:
            raise Denied("Unexpected launch context fields")
        Prompts(state).store_context(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True)
    if value["operation"] == "prompt_context":
        if set(body) != {"human_uid", "prompt_id"}:
            raise Denied("Unexpected context query fields")
        managed = Prompts(state).context(**body, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, managed=managed)
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
