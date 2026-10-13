"""Linux request-only transport. No grant, stop, verification or execution endpoint.

The trusted service supplies an accepted AF_UNIX SOCK_SEQPACKET connection and
its private State. The listener must enable SO_PASSCRED before accepting requests.
Systemd/socket provisioning and PAM control are separate work.
"""

import array
import json
import os
import socket
import struct
import time
from dataclasses import dataclass

from .approvals import Approvals
from .protocol import MAX_PACKET, ActionRequest, canonical, identifier, unique_object
from .state import Denied

CREDENTIALS = struct.Struct("3i")


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def receive(connection):
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_SEQPACKET:
        raise Denied("Expected local packet transport")
    peer = Peer(
        *CREDENTIALS.unpack(
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)
        )
    )
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    # Accommodate and close every possible Linux SCM_RIGHTS descriptor (max253).
    packet, ancillary, flags, _ = connection.recvmsg(
        MAX_PACKET,
        socket.CMSG_SPACE(CREDENTIALS.size) + socket.CMSG_SPACE(253 * 4),
        socket.MSG_CMSG_CLOEXEC,
    )
    credentials = []
    unexpected = False
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array("i")
            descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
            for fd in descriptors:
                os.close(fd)
            unexpected = True
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            if len(data) != CREDENTIALS.size:
                unexpected = True
            else:
                credentials.append(Peer(*CREDENTIALS.unpack(data)))
        else:
            unexpected = True
    if (
        unexpected
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or len(credentials) != 1
        or credentials[0] != peer
        or not packet
    ):
        raise Denied("Truncated packet, inherited connection or unexpected ancillary data")
    return peer, packet


def public_action(row):
    return {key: row[key] for key in ("id", "task_id", "state", "exit_code", "verified")}


def dispatch(state, packet, *, peer, now, boot_id):
    value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {"schema_version", "operation", "body"}:
        raise Denied("Unknown request envelope")
    if value["schema_version"] != "1.0":
        raise Denied("Unknown IPC version")
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
