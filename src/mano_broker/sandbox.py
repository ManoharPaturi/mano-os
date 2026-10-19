"""Fixed network-off FD sandbox profile, trusted launcher API only.

The caller supplies broker-held workspace/cwd descriptors, never model paths.
This compiles a command; it does not grant authority, launch or verify effects.
"""

import fcntl
import grp
import os
import pwd
import stat
import sys
from pathlib import Path

from mano_lab.sandbox import require_patched

from .protocol import text

GUARD = Path("/usr/libexec/mano-sandbox-guard")


def guard():
    for path in (GUARD, *GUARD.parents):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise PermissionError("Untrusted native sandbox guard")
    if not stat.S_ISREG(GUARD.stat().st_mode) or not GUARD.stat().st_mode & 0o111:
        raise PermissionError("Missing executable native sandbox guard")
    return str(GUARD)


def command(workspace_fd, cwd_fd, argv, *, task_pty=False):
    if type(task_pty) is not bool:
        raise ValueError('Explicit task PTY mode required')
    if sys.platform != "linux" or os.geteuid() == 0:
        raise PermissionError("Unprivileged Linux task identity required")
    account = pwd.getpwuid(os.geteuid())
    broker = pwd.getpwnam("mano-broker")
    request = grp.getgrnam("mano-request")
    if (
        not account.pw_name.startswith("mano-task-")
        or account.pw_uid < 1000
        or account.pw_gid != os.getegid()
        or set(os.getgroups()) - {account.pw_gid, request.gr_gid}
        or account.pw_shell != "/usr/sbin/nologin"
        or account.pw_dir != "/nonexistent"
    ):
        raise PermissionError("Task account policy mismatch")
    if type(workspace_fd) is not int or type(cwd_fd) is not int or workspace_fd == cwd_fd:
        raise ValueError("Distinct trusted workspace/cwd descriptors required")
    infos = []
    for fd in (workspace_fd, cwd_fd):
        info = os.fstat(fd)
        if (
            fd < 3
            or not stat.S_ISDIR(info.st_mode)
            or not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH
            or os.get_inheritable(fd)
        ):
            raise ValueError("Expected non-inheritable O_PATH directory")
        infos.append(info)
    if (
        infos[0].st_uid != broker.pw_uid
        or infos[0].st_gid != account.pw_gid
        or stat.S_IMODE(infos[0].st_mode) != 0o2770
        or infos[0].st_dev != infos[1].st_dev
    ):
        raise ValueError("Workspace identity/privacy mismatch")
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise ValueError("Bounded argv required")
    for index, arg in enumerate(argv):
        text(arg, allow_empty=index > 0)
    require_patched()  # Fail closed; no unsandboxed or old-package fallback.
    native = guard()
    return [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--unshare-user",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--tmpfs",
        "/usr/lib/mano-os",
        "--tmpfs",
        "/usr/lib/mano-broker",
        "--tmpfs",
        "/usr/libexec",
        "--ro-bind",
        native,
        "/task-guard",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/etc",
        "--dir",
        "/run",
        "--dir",
        "/home/task",
        "--dir",
        "/workspace",
        "--dir",
        "/task-cwd",
        "--bind-fd",
        str(workspace_fd),
        "/workspace",
        "--bind-fd",
        str(cwd_fd),
        "/task-cwd",
        "--chdir",
        "/task-cwd",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/home/task",
        "--setenv",
        "LANG",
        "C.UTF-8",
        *(["--setenv", "TERM", "xterm-256color"] if task_pty else []),
        "--",
        "/task-guard",
        *(["--task-pty"] if task_pty else []),
        *argv,
    ]
