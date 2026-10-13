"""Private broker transport; one root process identity per client lifetime.

This adapter carries trusted descriptors, never accepts model-selected socket
paths, and never retries uncertain launches. Journal coupling belongs to Runtime.
"""

import array
import json
import os
import select
import socket

from .ipc import CREDENTIALS, Peer
from .launch_transport import PATHS
from .protocol import MAX_PACKET, canonical, unique_object
from .state import Denied


def reply(connection):
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
        or peers[0].uid != 0
        or peers[0].gid != 0
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


class Client:
    def __init__(self):
        self.peer = None
        self.pidfd = None
        self.closed = False

    def exchange(self, channel, envelope, descriptors=()):
        if self.closed or channel not in PATHS:
            raise Denied("Closed or unknown launcher transport")
        if self.pidfd is not None and select.select([self.pidfd], [], [], 0)[0]:
            raise Denied("Launcher process exited; explicit recovery required")
        packet = canonical(envelope).encode()
        if len(packet) > MAX_PACKET or len(descriptors) != (2 if channel == "prepare" else 0):
            raise Denied("Invalid bounded launcher request")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(8)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.connect(PATHS[channel])
            creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size
            )))
            if creator.uid != 0 or creator.gid != 0:
                raise Denied("Launcher activation creator must be root")
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))]
            sent = connection.sendmsg([packet], ancillary if descriptors else [])
            if sent != len(packet):
                raise Denied("Incomplete private request; no retry")
            peer, value = reply(connection)
        if self.peer is None:
            fd = os.pidfd_open(peer.pid)
            if select.select([fd], [], [], 0)[0]:
                os.close(fd)
                raise Denied("Launcher exited before identity custody")
            self.peer, self.pidfd = peer, fd
        elif peer != self.peer:
            raise Denied("Launcher identity changed; no implicit recovery")
        return value

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
        self.closed = True
