"""Shared controlling-PTY harness, Root disposable guest only; not installed in product."""

import errno
import fcntl
import os
import pwd
import select
import subprocess
import termios
import time
from pathlib import Path


def native_terminal(module, arguments=(), *, actor=None, answers=()):
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
        "kvm",
        "qemu",
    }
    master, slave = os.openpty()
    child = os.fork()
    if child == 0:
        try:
            os.close(master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            if actor is not None:
                account = pwd.getpwnam(actor)
                os.fchown(slave, account.pw_uid, account.pw_gid)
                os.setgroups([])
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
            for target in (0, 1, 2):
                os.dup2(slave, target)
            if slave > 2:
                os.close(slave)
            os.execve(
                "/usr/bin/python3",
                ["python3", "-m", module, *arguments],
                {
                    "PYTHONPATH": "/usr/lib/mano-os",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                },
            )
        except BaseException:
            os._exit(125)  # Never run the Root test parent's cleanup from its child.
    os.close(slave)
    transcript = bytearray()
    phase = 0
    status = None
    closed = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([] if closed else [master], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = b""
                if not chunk:
                    closed = True
                transcript.extend(chunk)
                assert len(transcript) <= 8192
                if phase < len(answers) and answers[phase][0] in transcript:
                    os.write(master, answers[phase][1].encode("ascii") + b"\n")
                    phase += 1
            if status is None:
                exited, result = os.waitpid(child, os.WNOHANG)
                if exited:
                    status = result
            if status is not None and closed:
                break
        if status is None:
            exited, result = os.waitpid(child, os.WNOHANG)
            if exited:
                status = result
            else:
                os.kill(child, 9)
                _, status = os.waitpid(child, 0)
                raise AssertionError("Native terminal command exceeded bounded test deadline")
    finally:
        os.close(master)
        if status is None:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status), bytes(transcript)
