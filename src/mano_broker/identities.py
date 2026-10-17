"""Bounded trusted root task-account allocation, never a model-facing helper.

Accounts are intentionally retained: UID reuse requires separate proven teardown.
Partial failures also retain accounts rather than recycling outstanding authority.
"""

import fcntl
import grp
import os
import pwd
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

LOCK = Path("/run/mano-task-allocation.lock")
MAX_IDENTITIES = 64


@dataclass(frozen=True)
class TaskIdentity:
    name: str
    uid: int
    gid: int


def allocate_identity():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise PermissionError("Trusted Linux root allocation required")
    parent = LOCK.parent.lstat()
    if parent.st_uid != 0 or not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
        raise ValueError("Untrusted allocator lock parent")
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (
            info.st_uid != 0
            or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("Untrusted allocator lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        request = grp.getgrnam("mano-request")
        if request.gr_gid <= 0:
            raise ValueError("Unprivileged request group required")
        accounts = pwd.getpwall()
        if sum(p.pw_name.startswith("mano-task-") for p in accounts) >= MAX_IDENTITIES:
            raise ValueError("Task identity quota exhausted; teardown required")
        name = "mano-task-" + secrets.token_hex(7)
        subprocess.run(
            [
                "/usr/sbin/useradd",
                "--user-group",
                "--no-create-home",
                "--no-log-init",
                "--key",
                "CREATE_MAIL_SPOOL=no",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--password",
                "!",
                "--groups",
                "mano-request",
                name,
            ],
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=15,
        )
        account = pwd.getpwnam(name)
        primary = grp.getgrgid(account.pw_gid)
        password_status = subprocess.check_output(
            ["/usr/bin/passwd", "--status", name],
            text=True,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"},
            timeout=5,
        ).split()
        if (
            account.pw_uid < 1000
            or account.pw_gid <= 0
            or account.pw_gid == request.gr_gid
            or primary.gr_name != name
            or primary.gr_mem
            or account.pw_dir != "/nonexistent"
            or account.pw_shell != "/usr/sbin/nologin"
            or password_status[:2] != [name, "L"]
            or set(os.getgrouplist(name, account.pw_gid)) != {account.pw_gid, request.gr_gid}
            or any(p.pw_name != name and p.pw_gid == account.pw_gid for p in pwd.getpwall())
        ):
            raise ValueError("Task account isolation mismatch; account retained")
        return TaskIdentity(name, account.pw_uid, account.pw_gid)
    finally:
        os.close(fd)
