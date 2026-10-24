"""Fixed public request socket with authenticated broker replies and no retry."""

import base64
import hashlib
import os
import pwd
import select
import socket
import time

from mano_protocol.actions import MAX_PACKET, canonical
from mano_protocol.transport import CREDENTIALS, Peer, reply

PATH = '/run/mano-broker/request.sock'
OPERATIONS = {'request_approval', 'approval_status', 'propose', 'status', 'artifact_read',
              'model_result', 'file_result', 'terminal_output', 'terminal_output_read',
              'checkpoint_result', 'checkpoint_read', 'checkpoint_layout', 'restore_result',
              'package_catalog', 'package_install_review', 'package_apply_result',
              'pty_status', 'pty_read', 'pty_write', 'pty_resize', 'pty_close', 'file_write_result'}


def terminal_output(client, *, task_id, action_id):
    from mano_protocol.actions import identifier
    from mano_protocol.terminal_output import metadata

    identifier(task_id)
    identifier(action_id)
    response = client(dict(schema_version='1.0', operation='terminal_output',
        body=dict(task_id=task_id, action_id=action_id)))
    if (not isinstance(response, dict) or response.get('schema_version') != '1.0'
            or response.get('ok') is not True or 'output' not in response):
        raise ValueError('Invalid terminal output availability response')
    value = response['output']
    return None if value is None else metadata(value, task_id=task_id, action_id=action_id)


def read_terminal_output(client, *, task_id, action_id):
    from mano_protocol.terminal_output import metadata as parse_metadata

    meta = terminal_output(client, task_id=task_id, action_id=action_id)
    if meta is None:
        raise ValueError('Terminal output was not captured')
    streams = {}
    requested = False
    for stream in ('stdout', 'stderr'):
        data = bytearray()
        size = meta['streams'][stream]['size']
        while len(data) < size:
            if requested:
                time.sleep(0.11)  # Stay below the broker's global10requests/s budget.
            requested = True
            response = client(dict(schema_version='1.0', operation='terminal_output_read',
                body=dict(task_id=task_id, action_id=action_id, stream=stream,
                          offset=len(data), length=4096)))
            if (not isinstance(response, dict) or response.get('ok') is not True
                    or response.get('schema_version') != '1.0'
                    or type(response.get('eof')) is not bool
                    or not isinstance(response.get('data'), str)
                    or parse_metadata(response.get('output'), task_id=task_id,
                                      action_id=action_id) != meta):
                raise ValueError('Terminal output identity changed')
            piece = base64.b64decode(response['data'], validate=True)
            if (len(piece) != min(4096, size - len(data))
                    or response['eof'] != (len(data) + len(piece) == size)):
                raise ValueError('Invalid terminal output chunk/end')
            data.extend(piece)
        if hashlib.sha256(data).hexdigest() != meta['streams'][stream]['sha256']:
            raise ValueError('Terminal output digest mismatch')
        streams[stream] = bytes(data)
    return dict(metadata=meta, **streams)


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


def read_file_result(client, *, task_id, action_id, path):
    """Retrieve exact bounded bytes; do not disclose them to a model or interpret them."""
    from mano_protocol.actions import identifier, relative_path
    from mano_protocol.file_results import metadata as parse_metadata

    identifier(task_id)
    identifier(action_id)
    relative_path(path)
    data, metadata = bytearray(), None
    while True:
        response = client(dict(schema_version='1.0', operation='file_result',
            body=dict(task_id=task_id, action_id=action_id, offset=len(data), length=4096)))
        if (not isinstance(response, dict) or response.get('ok') is not True
                or response.get('schema_version') != '1.0'
                or type(response.get('eof')) is not bool
                or not isinstance(response.get('data'), str)):
            raise ValueError('Invalid file custody response')
        current = parse_metadata(response.get('artifact'), task_id=task_id,
                                 action_id=action_id, path=path)
        if metadata is None:
            metadata = current
        elif current != metadata:
            raise ValueError('File custody changed during retrieval')
        piece = base64.b64decode(response['data'], validate=True)
        if len(piece) != min(4096, metadata['size'] - len(data)):
            raise ValueError('Invalid file custody chunk')
        data.extend(piece)
        if response['eof'] != (len(data) == metadata['size']):
            raise ValueError('Invalid file custody end')
        if response['eof']:
            if hashlib.sha256(data).hexdigest() != metadata['sha256']:
                raise ValueError('File custody digest mismatch')
            return dict(metadata=metadata, data=bytes(data))


def file_write_result(client, *, task_id, action_id, path):
    """Historical publication receipt; does not establish current file contents."""
    from mano_protocol.actions import identifier
    from mano_protocol.file_writes import metadata

    response = client(dict(schema_version='1.0', operation='file_write_result',
        body=dict(task_id=identifier(task_id), action_id=identifier(action_id))))
    if (response.get('ok') is not True or response.get('schema_version') != '1.0'
            or 'publication' not in response):
        raise ValueError('Invalid write publication response')
    value = response['publication']
    return (None if value is None else
            metadata(value, task_id=task_id, action_id=action_id, path=path))
