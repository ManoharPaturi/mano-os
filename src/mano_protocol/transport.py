"""Kernel-authenticated packet replies; no policy, journal or privileged paths."""

import array
import json
import os
import socket
import struct
from dataclasses import dataclass

from .actions import MAX_PACKET, unique_object
from .errors import Denied

CREDENTIALS = struct.Struct("3i")


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def reply(connection, *, expected_uid=0, expected_gid=0):
    packet, ancillary, flags, _ = connection.recvmsg(
        MAX_PACKET,
        socket.CMSG_SPACE(CREDENTIALS.size) + socket.CMSG_SPACE(253 * 4),
        socket.MSG_CMSG_CLOEXEC,
    )
    peers = []
    unexpected = False
    for level, kind, data in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            rights = array.array("i")
            rights.frombytes(data[: len(data) - len(data) % rights.itemsize])
            for fd in rights:
                os.close(fd)
            unexpected = True
        elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS):
            if len(data) == CREDENTIALS.size:
                peers.append(Peer(*CREDENTIALS.unpack(data)))
            else:
                unexpected = True
        else:
            unexpected = True
    if (
        unexpected
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or len(peers) != 1
        or peers[0].uid != expected_uid
        or peers[0].gid != expected_gid
        or peers[0].pid <= 0
        or not packet
    ):
        raise Denied("Unauthenticated launcher response")
    value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0"
        or type(value.get("ok")) is not bool
    ):
        raise Denied("Invalid launcher response envelope")
    return peers[0], value

