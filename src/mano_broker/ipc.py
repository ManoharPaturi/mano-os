"""Linux request-only transport. No grant, stop, verification or execution endpoint.

The trusted service supplies an accepted AF_UNIX SOCK_SEQPACKET connection and
its private State. The listener must enable SO_PASSCRED before accepting requests.
Systemd/socket provisioning and PAM control are separate work.
"""

import base64
import hashlib
import json
import time

from mano_protocol.transport import CREDENTIALS as CREDENTIALS
from mano_protocol.transport import Peer as Peer
from mano_protocol.transport import receive as receive

from .approvals import Approvals
from .artifacts import durable_chunk
from .protocol import ActionRequest, canonical, identifier, unique_object
from .state import Denied


def public_action(row):
    proposal = json.loads(row["request_json"])
    del proposal["grant_id"]
    result = {key: row[key] for key in ("id", "task_id", "state", "exit_code", "verified")}
    result["proposal_digest"] = hashlib.sha256(canonical(proposal).encode()).hexdigest()
    return result


def dispatch(state, packet, *, peer, now, boot_id):
    value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {"schema_version", "operation", "body"}:
        raise Denied("Unknown request envelope")
    if value["schema_version"] != "1.0":
        raise Denied("Unknown IPC version")
    if value['operation'] in {'terminal_output', 'terminal_output_read'}:
        from .terminal_output import chunk, read

        body = value['body']
        fields = {'task_id', 'action_id'}
        if value['operation'] == 'terminal_output_read':
            fields |= {'stream', 'offset', 'length'}
        if not isinstance(body, dict) or set(body) != fields:
            raise Denied('Unknown terminal output fields')
        if value['operation'] == 'terminal_output':
            result = read(state, **body, caller_uid=peer.uid, boot_id=boot_id)
            return dict(schema_version='1.0', ok=True, output=None if result is None else result[0])
        result = chunk(state, **body, caller_uid=peer.uid, boot_id=boot_id)
        return dict(schema_version='1.0', ok=True, output=result['metadata'],
                    data=base64.b64encode(result['data']).decode('ascii'), eof=result['eof'])
    if value['operation'] in {'checkpoint_result', 'checkpoint_read'}:
        from .checkpoints import read

        body = value['body']
        fields = {'task_id', 'action_id'}
        if value['operation'] == 'checkpoint_read':
            fields |= {'offset', 'length'}
        if not isinstance(body, dict) or set(body) != fields:
            raise Denied('Unexpected checkpoint result fields')
        keys = {key: body[key] for key in ('task_id', 'action_id')}
        receipt, data = read(state, **keys, caller_uid=peer.uid, boot_id=boot_id)
        if value['operation'] == 'checkpoint_result':
            return dict(schema_version='1.0', ok=True, checkpoint=receipt)
        offset, length = body['offset'], body['length']
        if (type(offset) is not int or not 0 <= offset <= len(data)
                or type(length) is not int or not 1 <= length <= 16384):
            raise Denied('Invalid bounded checkpoint byte range')
        piece = data[offset:offset+length]
        return dict(schema_version='1.0', ok=True, checkpoint=receipt,
                    data=base64.b64encode(piece).decode('ascii'), eof=offset+len(piece)==len(data))
    if value['operation'] == 'file_write_result':
        from .file_writes import result

        body = value['body']
        if not isinstance(body, dict) or set(body) != {'task_id', 'action_id'}:
            raise Denied('Unknown write result fields')
        metadata = result(state, **body, caller_uid=peer.uid, boot_id=boot_id)
        return dict(schema_version='1.0', ok=True, publication=metadata)
    if value['operation'] == 'file_result':
        from .file_reads import result_chunk

        body = value['body']
        if not isinstance(body, dict) or set(body) != {'task_id', 'action_id', 'offset', 'length'}:
            raise Denied('Unknown file result fields')
        result = result_chunk(state, **body, caller_uid=peer.uid, boot_id=boot_id)
        return dict(schema_version='1.0', ok=True, artifact=result['metadata'],
                    data=base64.b64encode(result['data']).decode('ascii'), eof=result['eof'])
    if value["operation"] == "model_result":
        from .models import ModelStore

        body = value["body"]
        if not isinstance(body, dict) or set(body) != {"task_id", "action_id", "offset", "length"}:
            raise Denied("Unknown model result fields")
        result = ModelStore(state).chunk(**body, caller_uid=peer.uid, boot_id=boot_id)
        return dict(schema_version="1.0", ok=True, result=result["metadata"],
                    data=base64.b64encode(result["data"]).decode("ascii"), eof=result["eof"])
    if value["operation"] == "artifact_read":
        body = value["body"]
        if (not isinstance(body, dict)
                or set(body) != {"task_id", "artifact_id", "offset", "length"}):
            raise Denied("Unknown artifact read fields")
        result = durable_chunk(state, body["artifact_id"], task_id=body["task_id"],
                               caller_uid=peer.uid, boot_id=boot_id,
                               offset=body["offset"], length=body["length"])
        return dict(schema_version="1.0", ok=True, artifact=result["metadata"],
                    data=base64.b64encode(result["data"]).decode("ascii"), eof=result["eof"])
    if value["operation"] == "request_approval":
        pending = Approvals(state).request(
            value["body"], caller_uid=peer.uid, now=now, boot_id=boot_id
        )
        return {"schema_version": "1.0", "ok": True, "approval": pending}
    if value["operation"] == "approval_status":
        body = value["body"]
        if not isinstance(body, dict) or set(body) != {"approval_id"}:
            raise Denied("Unknown approval status fields")
        status = Approvals(state).status(
            body["approval_id"], caller_uid=peer.uid, now=now, boot_id=boot_id
        )
        return {"schema_version": "1.0", "ok": True, "approval": status}
    if value["operation"] == "propose":
        request = ActionRequest.parse(canonical(value["body"]).encode())
        row, fresh = state.authorize(request, caller_uid=peer.uid, now=now, boot_id=boot_id)
        return {"schema_version": "1.0", "ok": True, "fresh": fresh, "action": public_action(row)}
    if value["operation"] == "status":
        body = value["body"]
        if not isinstance(body, dict) or set(body) != {"task_id", "action_id"}:
            raise Denied("Unknown status fields")
        identifier(body["task_id"])
        identifier(body["action_id"])
        row = state.db.execute(
            "SELECT a.* FROM actions a JOIN tasks t ON a.task_id=t.id "
            "WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=?",
            (body["action_id"], body["task_id"], peer.uid, boot_id),
        ).fetchone()
        if row is None:
            raise Denied("Action unavailable to this caller")
        return {"schema_version": "1.0", "ok": True, "action": public_action(row)}
    raise Denied("Operation not exposed to core")


def serve_connection(state, connection, *, boot_id):
    """One bounded request; derive identity from kernel, never JSON. No effects run."""
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)
        result = dispatch(state, packet, peer=peer, now=time.monotonic(), boot_id=boot_id)
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        # Do not disclose task/grant existence, private arguments, DB paths or exceptions.
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    try:
        connection.sendall(canonical(result).encode())
    except OSError:
        pass  # Reservation remains journaled even if requester disappears.
