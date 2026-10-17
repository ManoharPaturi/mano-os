"""Linux sealed provider bytes on a private broker/service connection only."""

import array
import fcntl
import hashlib
import os
import re
import socket
import stat

from .actions import canonical, identifier, text
from .provider import MAX_RESPONSE, decode
from .transport import CREDENTIALS, Peer


def validate_binding(binding):
    if not isinstance(binding, dict) or set(binding) != {
            'task_id', 'action_id', 'boot_id', 'nonce', 'request_sha256'}:
        raise ValueError('Invalid provider job binding')
    identifier(binding['task_id'])
    identifier(binding['action_id'])
    text(binding['boot_id'], 128)
    for key in ('nonce', 'request_sha256'):
        if not isinstance(binding[key], str) or not re.fullmatch('[a-f0-9]{64}', binding[key]):
            raise ValueError('Invalid provider job digest or nonce')


def required_seals():
    return fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def send_response(connection, packet, *, binding):
    validate_binding(binding)
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_SEQPACKET:
        raise ValueError('Private provider packet connection required')
    if not isinstance(packet, bytes) or not 1 <= len(packet) <= MAX_RESPONSE:
        raise ValueError('Invalid bounded provider response')
    fd = os.memfd_create('mano-provider-response', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(packet):
            written = os.write(fd, packet[offset:])
            if written <= 0:
                raise OSError('Incomplete sealed response write')
            offset += written
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, required_seals())
        metadata = canonical(dict(schema_version='1.0', ok=True, binding=binding,
            size=len(packet), sha256=hashlib.sha256(packet).hexdigest())).encode()
        sent = connection.sendmsg([metadata], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                              array.array('i', [fd]))])
        if sent != len(metadata):
            raise OSError('Incomplete response handoff; do not repeat the model call')
    finally:
        os.close(fd)


def receive_response(connection, *, binding, expected_uid, expected_gid):
    validate_binding(binding)
    if (connection.family != socket.AF_UNIX or connection.type != socket.SOCK_SEQPACKET
            or type(expected_uid) is not int or expected_uid <= 0
            or type(expected_gid) is not int or expected_gid <= 0):
        raise ValueError('Private provider service packet connection required')
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    packet, ancillary, flags, _ = connection.recvmsg(8192,
        socket.CMSG_SPACE(CREDENTIALS.size) + socket.CMSG_SPACE(253 * 4), socket.MSG_CMSG_CLOEXEC)
    fds, peers = [], []
    unexpected = False
    try:
        for level, kind, data in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                descriptors = array.array('i')
                descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
                fds.extend(descriptors)
                unexpected |= len(data) % descriptors.itemsize != 0
            elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS):
                if len(data) == CREDENTIALS.size:
                    peers.append(Peer(*CREDENTIALS.unpack(data)))
                else:
                    unexpected = True
            else:
                unexpected = True
        if (unexpected or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(fds) != 1 or len(peers) != 1 or peers[0].pid <= 0
                or (peers[0].uid, peers[0].gid) != (expected_uid, expected_gid)):
            raise ValueError('Unauthenticated provider descriptor handoff')
        value = decode(packet, 8192)
        if (not isinstance(value, dict)
                or set(value) != {'schema_version', 'ok', 'binding', 'size', 'sha256'}
                or value['schema_version'] != '1.0' or value['ok'] is not True
                or value['binding'] != binding or type(value['size']) is not int
                or not 1 <= value['size'] <= MAX_RESPONSE):
            raise ValueError('Provider response job binding mismatch')
        fd = fds[0]
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != value['size']
                or os.get_inheritable(fd)
                or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required_seals() != required_seals()):
            raise ValueError('Provider response is not immutable bounded custody')
        # pread ignores the descriptor's shared offset; sender cannot race seeks.
        response = os.pread(fd, value['size'], 0)
        if (len(response) != value['size']
                or hashlib.sha256(response).hexdigest() != value['sha256']):
            raise ValueError('Provider sealed response digest mismatch')
        return response
    finally:
        for fd in fds:
            os.close(fd)
