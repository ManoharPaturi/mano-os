"""Private broker transport; one root process identity per client lifetime.

This adapter carries trusted descriptors, never accepts model-selected socket
paths, and never retries uncertain launches. Journal coupling belongs to Runtime.
"""

import array
import os
import select
import socket

from mano_protocol.transport import CREDENTIALS, Peer
from mano_protocol.transport import reply as reply

from .launch_transport import PATHS
from .protocol import MAX_PACKET, canonical
from .state import Denied


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
