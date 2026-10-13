"""Fixed public request socket with authenticated broker replies and no retry."""

import os
import pwd
import select
import socket

from mano_protocol.actions import MAX_PACKET, canonical
from mano_protocol.transport import CREDENTIALS, Peer, reply

PATH = '/run/mano-broker/request.sock'
OPERATIONS = {'request_approval', 'approval_status', 'propose', 'status', 'artifact_read'}


class BrokerClient:
    def __init__(self):
        account = pwd.getpwnam('mano-broker')
        if account.pw_uid == 0:
            raise ValueError('Broker must have a separate service identity')
        self.uid, self.gid = account.pw_uid, account.pw_gid
        self.peer = None
        self.pidfd = None
        self.closed = False

    def __call__(self, envelope):
        if self.closed or envelope.get('operation') not in OPERATIONS:
            raise ValueError('Closed or unsupported public operation')
        packet = canonical(envelope).encode()
        if len(packet) > MAX_PACKET:
            raise ValueError('Oversize public request')
        if self.pidfd is not None and select.select([self.pidfd], [], [], 0)[0]:
            raise ValueError('Broker exited; reconcile with a new client')
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(3)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.connect(PATH)
            creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
            if creator.uid != 0 or creator.gid != 0:
                raise ValueError('Public listener must be root activated')
            if connection.send(packet) != len(packet):
                raise ValueError('Incomplete request; do not retry effects')
            peer, result = reply(connection, expected_uid=self.uid, expected_gid=self.gid)
        if self.peer is None:
            fd = os.pidfd_open(peer.pid)
            if select.select([fd], [], [], 0)[0]:
                os.close(fd)
                raise ValueError('Broker exited before identity custody')
            self.peer, self.pidfd = peer, fd
        elif peer != self.peer:
            raise ValueError('Broker identity changed; explicit reconciliation required')
        return result

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
        self.closed = True
