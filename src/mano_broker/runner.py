"""Bounded unprivileged sandbox process runner; not a broker execution endpoint.

Trusted launch code must supply held FDs and a live revocation observer. Process
exit/output is evidence only; it never marks a task effect independently verified.
"""

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

from mano_protocol.terminal_output import STREAM_LIMIT as OUTPUT_LIMIT

from .sandbox import command


@dataclass(frozen=True)
class ProcessResult:
    reason: str
    return_code: int | None
    stdout: bytes
    stderr: bytes


def run(workspace_fd, cwd_fd, argv, *, timeout, revoked):
    if type(timeout) is not int or not 1 <= timeout <= 300 or not callable(revoked):
        raise ValueError("Trusted deadline and revocation observer required")

    def is_revoked():
        value = revoked()
        if type(value) is not bool:
            raise ValueError("Revocation observer must return a boolean")
        return value

    if is_revoked():
        return ProcessResult("revoked", None, b"", b"")
    args = command(workspace_fd, cwd_fd, argv)
    if is_revoked():
        return ProcessResult("revoked", None, b"", b"")
    process = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        close_fds=True,
        pass_fds=(workspace_fd, cwd_fd),
        start_new_session=True,
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    reason = "completed"
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name in buffers:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                if is_revoked():
                    reason = "revoked"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timed-out"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    available = OUTPUT_LIMIT - len(buffer)
                    buffer.extend(chunk[:available])
                    if len(chunk) > available:
                        reason = "output-limit"
                        break
                if reason != "completed":
                    break
            # Pipes can close before a process exits; still enforce the deadline
            # and revocation, rather than doing an unbounded wait after EOF.
            while reason == "completed" and process.poll() is None:
                if is_revoked():
                    reason = "revoked"
                    break
                if time.monotonic() >= deadline:
                    reason = "timed-out"
                    break
                time.sleep(0.01)
    finally:
        # Always terminate the owned outer process group. Bubblewrap's PID
        # namespace/die-with-parent must also reap inner sessions; CI tests it.
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        finally:
            process.stdout.close()
            process.stderr.close()
    return ProcessResult(
        reason, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
    )
