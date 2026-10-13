"""Narrow trusted provisioning receiver; daemon/installer integration remains separate.

Exactly one root-supplied O_PATH directory FD, never an untrusted root pathname.
"""

import array
import fcntl
import json
import os
import pwd
import socket
import stat

from .ipc import CREDENTIALS, Peer
from .protocol import MAX_PACKET, canonical, unique_object
from .state import Denied


def receive_directory(connection):
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_SEQPACKET:
        raise Denied("Expected private packet provisioning transport")
    peer = Peer(
        *CREDENTIALS.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    )
    # Drain one bounded packet before denying, closing all passed rights. Closing
    # an unread seqpacket can reset the peer before its denial response is read.
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    packet, ancillary, flags, _ = connection.recvmsg(
        MAX_PACKET, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4), socket.MSG_CMSG_CLOEXEC
    )
    descriptors = []
    senders = []
    unexpected = False
    try:
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array("i")
                fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
                descriptors.extend(fds)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                senders.append(Peer(*CREDENTIALS.unpack(data)))
            else:
                unexpected = True
        if (
            peer.uid != 0
            or unexpected
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or not packet
            or len(descriptors) != 1
            or senders != [peer]
        ):
            raise Denied("Invalid root descriptor packet")
        fd = descriptors[0]
        if not stat.S_ISDIR(os.fstat(fd).st_mode) or not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH:
            raise Denied("Expected pinned directory descriptor")
        if os.get_inheritable(fd):
            raise Denied("Inheritable provisioning descriptor")
        return peer, packet, descriptors.pop()
    finally:
        for fd in descriptors:
            os.close(fd)


def provision_task(state, registry, packet, *, peer, directory_fd, boot_id):
    if peer.uid != 0:
        raise Denied("Provisioning requires root adapter")
    value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "operation", "body"}
        or value["schema_version"] != "1.0"
        or value["operation"] != "provision_task"
        or not isinstance(value["body"], dict)
    ):
        raise Denied("Unknown provisioning envelope")
    body = value["body"]
    if set(body) != {"human_uid", "caller_uid", "mode", "classification"}:
        raise Denied("Unknown provisioning fields")
    if type(body["caller_uid"]) is not int or body["caller_uid"] <= 0:
        raise Denied("Expected unprivileged caller UID")
    info = os.fstat(directory_fd)
    account = pwd.getpwuid(body["caller_uid"])
    if (
        account.pw_gid <= 0
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != account.pw_gid
        or stat.S_IMODE(info.st_mode) not in {0o770, 0o2770}
        or not fcntl.fcntl(directory_fd, fcntl.F_GETFL) & os.O_PATH
    ):
        raise Denied("Workspace owner/group/privacy does not match broker/task")
    resource = registry.register(
        directory_fd, human_uid=body["human_uid"], caller_uid=body["caller_uid"], boot_id=boot_id
    )
    try:
        task = state.create_task(
            human_uid=body["human_uid"],
            caller_uid=body["caller_uid"],
            mode=body["mode"],
            classification=body["classification"],
            resource_id=resource,
            boot_id=boot_id,
        )
        registry.resources[resource].task_id = task
    except BaseException:
        registry.resources.pop(resource).workspace.close()
        raise
    return {"schema_version": "1.0", "ok": True, "task_id": task, "resource_id": resource}


def serve_provision(state, registry, connection, *, boot_id):
    connection.settimeout(2)
    fd = None
    try:
        peer, packet, fd = receive_directory(connection)
        result = provision_task(
            state, registry, packet, peer=peer, directory_fd=fd, boot_id=boot_id
        )
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    finally:
        if fd is not None:
            os.close(fd)
    try:
        connection.sendall(canonical(result).encode())
    except OSError:
        pass  # Committed task/FD remains broker-owned; no effect executed.
