"""Bounded private operator logs; never a public/model result or authority record."""

import contextlib
import os
import stat

from mano_broker.package_catalog import trusted
from mano_runtime import package_attempts, recovery

BASE = recovery.BASE / 'package-logs'
MAX_BYTES = 1024 * 1024


@contextlib.contextmanager
def capture(attempt_id):
    recovery.root_guard()
    package_attempts.identifier(attempt_id)
    package_attempts.record(package_attempts.BASE / attempt_id / 'intent.json')
    trusted(recovery.BASE, directory=True)
    BASE.mkdir(mode=0o700, exist_ok=True)
    info = trusted(BASE, directory=True)
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise PermissionError('Private Root package log custody required')
    entries = list(BASE.iterdir())
    if len(entries) >= package_attempts.MAX_ATTEMPTS:
        raise ValueError('Package log retention requires operator review')
    for path in entries:
        package_attempts.identifier(path.name)
        info = trusted(path, directory=True)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Private Root attempt log custody required')
    directory = BASE / attempt_id
    directory.mkdir(mode=0o700)  # Never replace/reuse a prior attempt's logs.
    streams = {}
    total = 0
    try:
        for name in ('stdout', 'stderr'):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            streams[name] = os.fdopen(fd, 'wb')
        package_attempts.sync(directory)
        package_attempts.sync(BASE)
        package_attempts.sync(recovery.BASE)

        def emit(channel, data):
            nonlocal total
            if channel not in streams or not isinstance(data, bytes):
                raise ValueError('Fixed package log channel and bytes required')
            total += len(data)
            if total > MAX_BYTES:
                raise ValueError('Package operator log exceeds byte budget')
            streams[channel].write(data)

        yield emit
    finally:
        failure = None
        for stream in streams.values():
            try:
                stream.flush()
                os.fsync(stream.fileno())
            except OSError as error:
                failure = failure or error
            finally:
                stream.close()
        if failure is not None:
            raise failure
