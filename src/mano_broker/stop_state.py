"""Read-only consumption of native root Stop authority; never rearm it here."""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .state import Denied

STATE_FILE = Path("/var/lib/mano-stopd/state")


@dataclass(frozen=True)
class Snapshot:
    generation: int
    latched: bool


def parse(value):
    match = re.fullmatch(rb"v1:(0|[1-9][0-9]{0,18}):(armed|latched)\n", value)
    if match is None or int(match[1]) > (1 << 63) - 1:
        raise Denied("Malformed native Stop generation")
    return Snapshot(int(match[1]), match[2] == b"latched")


def no_pending():
    try:
        STATE_FILE.with_name("state.pending").lstat()
    except FileNotFoundError:
        return
    raise Denied("Native Stop write or recovery pending")


def snapshot():
    for path in STATE_FILE.parents:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise Denied("Untrusted native Stop state parent")
    no_pending()
    fd = os.open(STATE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o644 or not 1 <= info.st_size < 64):
            raise Denied("Invalid native Stop state metadata")
        value = os.read(fd, 64)
        if len(value) != info.st_size:
            raise Denied("Native Stop state corrupt or changing")
        result = parse(value)
        no_pending()
        return result
    finally:
        os.close(fd)


def latched():
    return snapshot().latched


def require_armed():
    if latched():
        raise Denied("Native emergency Stop latched")
