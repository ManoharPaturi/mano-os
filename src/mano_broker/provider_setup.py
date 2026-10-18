"""Root native-terminal credential installation; no activation, rotation or API call."""

import getpass
import os
import re
import secrets
import stat
import sys
import warnings
from pathlib import Path

from mano_protocol.actions import canonical
from mano_protocol.stop_state import snapshot

DIRECTORY = Path('/etc/mano/credentials')
EVENTS = Path('/sys/fs/cgroup/mano.slice/mano-core.slice/cgroup.events')


def operator_terminal():
    if sys.platform != 'linux' or (os.getuid(), os.geteuid(), os.getegid()) != (0, 0, 0):
        raise PermissionError('Native Linux Root operator required')
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('Native terminal required; no piped credentials')


def stopped(expected=None):
    current = snapshot()
    if not current.latched or (expected is not None and current != expected):
        raise ValueError('Unchanged native Stop latch required')
    for parent in EVENTS.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted native Stop cgroup parent')
    fd = os.open(EVENTS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise ValueError('Untrusted native Stop cgroup events')
        packet = os.read(fd, 256)
    finally:
        os.close(fd)
    fields = dict(line.split() for line in packet.decode('ascii').splitlines())
    if fields.get('populated') != '0':
        raise ValueError('Native Stop domain must be drained')
    return current


def directory():
    for parent in DIRECTORY.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted credential ancestor')
    try:
        DIRECTORY.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        created = False
    fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if created and info.st_uid == 0:
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Private Root credential directory required')
    except BaseException:
        os.close(fd)
        raise
    return fd


def absent(fd):
    try:
        os.stat('openai', dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError('Existing credential preserved; rotation is a separate operation')


def publish(fd, value, *, check):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,4096}', value):
        raise ValueError('Invalid bounded credential format')
    absent(fd)
    name = '.provider-key-' + secrets.token_hex(16)
    stage = None
    created = False
    try:
        stage = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        | os.O_CLOEXEC, 0o600, dir_fd=fd)
        created = True
        os.fchmod(stage, 0o600)
        packet = value.encode('ascii')
        offset = 0
        while offset < len(packet):
            written = os.write(stage, packet[offset:])
            if written <= 0:
                raise OSError('Incomplete credential staging')
            offset += written
        os.fsync(stage)
        os.close(stage)
        stage = None
        check()  # Native rearm/Stop change during typing or writing aborts before publication.
        os.link(name, 'openai', src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    finally:
        if stage is not None:
            os.close(stage)
        if created:
            os.unlink(name, dir_fd=fd)  # Only this invocation's exclusive staging name.
            os.fsync(fd)
    # Link creates atomically without replacing another operator's destination.
    # A crash with both links fails the provider's existing single-link guard.


def main():
    fd = None
    try:
        if len(sys.argv) != 1:
            raise ValueError('Credential setup accepts no arguments')
        operator_terminal()
        before = stopped()
        fd = directory()
        absent(fd)  # Refuse before asking for a secret if already provisioned.
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Provider API key: ')
            confirmation = getpass.getpass('Confirm API key: ')
        if value != confirmation:
            raise ValueError('Credential confirmation differs')
        publish(fd, value, check=lambda: stopped(before))
        print(canonical(dict(schema_version='1.0', ok=True, credential_installed=True,
                             activation_changed=False)))
        return 0
    except (OSError, ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print(canonical(dict(schema_version='1.0', ok=False, error='denied')))
        return 1
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
