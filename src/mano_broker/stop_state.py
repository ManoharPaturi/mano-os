"""Read-only consumption of native root Stop authority; never rearm it here."""

import os
import stat
from pathlib import Path

from .state import Denied

STATE_FILE = Path("/var/lib/mano-stopd/state")


def latched():
    for path in STATE_FILE.parents:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise Denied("Untrusted native Stop state parent")
    fd = os.open(STATE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o644 or info.st_size not in {6, 8}):
            raise Denied("Invalid native Stop state metadata")
        value = os.read(fd, 16)
        if len(value) != info.st_size or value not in {b"armed\n", b"latched\n"}:
            raise Denied("Native Stop state corrupt or changing")
        return value == b"latched\n"
    finally:
        os.close(fd)


def require_armed():
    if latched():
        raise Denied("Native emergency Stop latched")
