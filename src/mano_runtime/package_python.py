"""Existing Debian13 Python paths protected from package-maintainer writes.

This is one part of runtime protection, not a complete interpreter/ELF closure.
In particular, absent search-path entries and the shared dynamic loader remain
separate requirements. Keep that distinction in native evidence and approvals.
"""

import errno
import os
from pathlib import Path

REQUIRED = ('/usr/bin/python3.13', '/usr/lib/python3.13',
            '/usr/lib/python3', '/usr/local')
OPTIONAL = ('/etc/python3', '/etc/python3.13')


def verify_readonly(path):
    # ETXTBSY alone does not prove a read-only mount. An actively executing ELF
    # can reject write-open before the kernel checks mount writability.
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise PermissionError('Existing trusted Python path is writable')
    if Path(path).is_dir():
        candidate = path + '/.mano-package-boundary-' + os.urandom(16).hex()
        try:
            os.mkdir(candidate, 0o700)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            raise PermissionError('New Python module directory was writable')
    else:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            allowed = {errno.EROFS}
            if path == '/usr/bin/python3.13':
                allowed.add(errno.ETXTBSY)
            if error.errno not in allowed:
                raise
        else:
            os.close(fd)
            raise PermissionError('Existing Python interpreter opened for writing')

