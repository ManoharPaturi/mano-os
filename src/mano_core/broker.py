"""Fixed public request socket with authenticated broker replies and no retry."""

import base64
import hashlib
import os
import pwd
import select
import socket

from mano_protocol.actions import MAX_PACKET, canonical
from mano_protocol.transport import CREDENTIALS, Peer, reply

PATH = '/run/mano-broker/request.sock'
OPERATIONS = {'request_approval', 'approval_status', 'propose', 'status', 'artifact_read',
              'model_result'}


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


def read_model_result(client, *, task_id, action_id):
    """Reassemble read-only custody with fixed bounds and a stable identity/digest."""
    from mano_protocol.actions import identifier
    from mano_protocol.provider import decode

    identifier(task_id)
    identifier(action_id)
    data = bytearray()
    metadata = None
    while True:
        response = client(dict(schema_version='1.0', operation='model_result',
            body=dict(task_id=task_id, action_id=action_id, offset=len(data), length=4096)))
        current = response.get('result')
        if (response.get('ok') is not True or response.get('schema_version') != '1.0'
                or not isinstance(current, dict)
                or set(current) != {'task_id', 'action_id', 'size', 'sha256'}
                or current['task_id'] != task_id or current['action_id'] != action_id
                or type(current['size']) is not int or not 1 <= current['size'] <= 131072
                or not isinstance(current['sha256'], str) or len(current['sha256']) != 64
                or type(response.get('eof')) is not bool):
            raise ValueError('Invalid model custody metadata')
        if metadata is None:
            metadata = current.copy()
        elif current != metadata:
            raise ValueError('Model custody changed during read')
        piece = base64.b64decode(response.get('data'), validate=True)
        if not 1 <= len(piece) <= 4096 or len(data) + len(piece) > metadata['size']:
            raise ValueError('Invalid model custody chunk')
        data.extend(piece)
        if response['eof'] != (len(data) == metadata['size']):
            raise ValueError('Invalid model custody end')
        if response['eof']:
            if hashlib.sha256(data).hexdigest() != metadata['sha256']:
                raise ValueError('Model custody digest mismatch')
            return decode(bytes(data), 131072)
