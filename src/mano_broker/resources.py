"""Linux descriptor custody core; trusted provisioning only, not a public endpoint.

No execution/read/write is implemented here. FD pins identity, not immutable content.
"""

import ctypes
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .protocol import relative_path
from .state import Denied

LIBRARY = Path("/usr/lib/mano-broker/libmano-resources.so")


def library():
    # Never load an agent-selected binary or a writable development fallback.
    for path in (LIBRARY, *LIBRARY.parents):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise Denied("Untrusted native resource library path")
    if not stat.S_ISREG(LIBRARY.stat().st_mode):
        raise Denied("Resource library is not a regular file")
    loaded = ctypes.CDLL(str(LIBRARY), use_errno=True)
    loaded.mano_pin_beneath.argtypes = (ctypes.c_int, ctypes.c_char_p)
    loaded.mano_pin_beneath.restype = ctypes.c_int
    loaded.mano_read_pinned.argtypes = (ctypes.c_int,)
    loaded.mano_read_pinned.restype = ctypes.c_int
    return loaded


@dataclass
class Pinned:
    fd: int
    device: int
    inode: int

    def read_fd(self):
        if self.fd < 0:
            raise Denied("Closed resource pin")
        fd = library().mano_read_pinned(self.fd)
        if fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return fd

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Workspace:
    def __init__(self, trusted_directory_fd):
        info = os.fstat(trusted_directory_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise Denied("Resource anchor must be a trusted directory FD")
        self.fd = os.dup(trusted_directory_fd)
        self.device = info.st_dev
        self.inode = info.st_ino
        try:
            self.native = library()
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def pin(self, path, *, directory=False):
        if self.fd < 0:
            raise Denied("Closed resource anchor")
        relative_path(path)
        fd = self.native.mano_pin_beneath(self.fd, path.encode("utf8"))
        if fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        try:
            info = os.fstat(fd)
            valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
            if not valid or (not directory and info.st_nlink != 1):
                raise Denied("Unexpected target type or hardlinked regular file")
            if os.get_inheritable(fd):
                raise Denied("Inheritable target descriptor")
            return Pinned(fd, info.st_dev, info.st_ino)
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
