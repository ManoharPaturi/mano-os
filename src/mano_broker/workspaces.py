"""Trusted root administrative workspace creator; not setuid or a model tool.

Fixed root-owned parent, fresh directory, UID/GID policy and default ACLs. Only
operator code may provision. Runtime/executor adapters remain separate.
"""

import os
import pwd
import secrets
import stat
import subprocess
import sys
from pathlib import Path

BASE = Path("/var/lib/mano-workspaces")


def create_workspace(*, human_uid, caller_uid):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise PermissionError("Trusted Linux root provisioning required")
    if type(human_uid) is not int or type(caller_uid) is not int:
        raise ValueError("Expected trusted UID values")
    broker = pwd.getpwnam("mano-broker")
    human = pwd.getpwuid(human_uid)
    caller = pwd.getpwuid(caller_uid)
    if (
        human_uid < 1000
        or human.pw_name in {"mano-broker", "mano-core", "mano-worker", "mano-agent"}
        or caller_uid in {0, human_uid, broker.pw_uid}
        or caller_uid < 1000
        or caller.pw_gid <= 0
        or not (caller.pw_name == "mano-worker" or caller.pw_name.startswith("mano-task-"))
    ):
        raise ValueError("Invalid human/task identity policy")
    BASE.mkdir(mode=0o711, exist_ok=True)
    for path in (BASE, *BASE.parents):
        info = path.lstat()
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise ValueError("Untrusted workspace parent")
    base_fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    name = secrets.token_hex(16)
    directory_fd = None
    try:
        os.mkdir(name, mode=0o700, dir_fd=base_fd)
        directory_fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base_fd
        )
        os.fchown(directory_fd, broker.pw_uid, caller.pw_gid)
        os.fchmod(directory_fd, 0o2770)
        # Inherit broker/human access on worker-owned output files. The mask is
        # still constrained by each file's creation mode; private files may deny.
        acl = (
            f"u::rwx,u:{human_uid}:rwx,g::rwx,m::rwx,o::---,"
            f"d:u::rwx,d:u:{broker.pw_uid}:rwx,d:u:{human_uid}:rwx,"
            "d:g::rwx,d:m::rwx,d:o::---"
        )
        subprocess.run(
            ["/usr/bin/setfacl", "-m", acl, f"/proc/self/fd/{directory_fd}"],
            pass_fds=(directory_fd,),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            check=True,
        )
        result = os.open(
            name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base_fd
        )
        info = os.fstat(result)
        if (
            info.st_uid != broker.pw_uid
            or info.st_gid != caller.pw_gid
            or stat.S_IMODE(info.st_mode) != 0o2770
        ):
            os.close(result)
            raise ValueError("Workspace policy mismatch")
        return BASE / name, result
    except BaseException:
        # Only this fresh empty directory; never recursively delete user files.
        try:
            os.rmdir(name, dir_fd=base_fd)
        except OSError:
            pass
        raise
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(base_fd)
