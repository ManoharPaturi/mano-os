"""Pinned private systemd credential file reads; role-specific paths stay with callers."""

import os
import re
import stat
import struct


def private_mode(info, fd):
    mode = stat.S_IMODE(info.st_mode)
    if mode in {0o400, 0o600}:
        return True
    if mode != 0o440 or info.st_uid != 0:
        return False
    # systemd v257 prefers root ownership plus a named-user read ACL. The
    # ACL mask is reflected in group mode bits; do not grant arbitrary groups.
    packet = os.getxattr(fd, 'system.posix_acl_access')
    if len(packet) != 44 or struct.unpack_from('<I', packet)[0] != 2:
        return False
    entries = [struct.unpack_from('<HHI', packet, offset) for offset in range(4, 44, 8)]
    unused = 0xffffffff
    return entries == [(1, 4, unused), (2, 4, os.geteuid()), (4, 0, unused),
                       (16, 4, unused), (32, 0, unused)]


def private_file(directory, name, maximum):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name):
        raise ValueError('Unknown provider credential')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
            raise ValueError('Unsafe credential directory')
        file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(file)
            checks = {
                'credential-file-type': stat.S_ISREG(info.st_mode),
                'credential-file-owner': info.st_uid in {0, os.geteuid()},
                'credential-file-mode': private_mode(info, file),
                'credential-file-links': info.st_nlink == 1,
                'credential-file-size': 1 <= info.st_size <= maximum,
            }
            for code, valid in checks.items():
                if not valid:
                    raise ValueError(code)
            packet = os.read(file, maximum + 1)
            if len(packet) != info.st_size:
                raise ValueError('Provider credential changed')
            return packet
        finally:
            os.close(file)
    finally:
        os.close(fd)

