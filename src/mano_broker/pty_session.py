"""Unprivileged task PTY primitive; no public IPC, grants or Root TTY handles.

An authorized supervisor must drive this worker and own its cgroup. Input effects
are not idempotent; callers must journal before writing and never resend uncertain
input. Broker session authority and persistent transport are separate integration.
"""

import errno
import fcntl
import os
import signal
import struct
import subprocess
import termios
import time

from mano_protocol.terminal_output import STREAM_LIMIT

from .sandbox import command

INPUT_LIMIT = 65536


def geometry(rows, columns):
    if (type(rows) is not int or type(columns) is not int
            or not 1 <= rows <= 200 or not 1 <= columns <= 400):
        raise ValueError('Invalid bounded PTY geometry')
    return struct.pack('HHHH', rows, columns, 0, 0)


class TaskPTY:
    def __init__(self, workspace_fd, cwd_fd, argv, *, timeout, revoked, rows=24, columns=80):
        size = geometry(rows, columns)
        if type(timeout) is not int or not 1 <= timeout <= 300 or not callable(revoked):
            raise ValueError('Trusted PTY deadline and revocation observer required')
        self.revoked, self.process, self.master = revoked, None, -1
        self.closed, self.reason, self.return_code = False, 'running', None
        self.input_bytes, self.output_bytes = 0, 0
        self.deadline = time.monotonic() + timeout
        # Includes Linux/unprivileged task-account/FD/native guard/package checks.
        args = command(workspace_fd, cwd_fd, argv, task_pty=True)
        if self._revoked():
            raise PermissionError('PTY start revoked')
        slave = -1
        try:
            self.master, slave = os.openpty()
            for fd in (self.master, slave):
                os.set_inheritable(fd, False)
            attrs = termios.tcgetattr(slave)
            attrs[1] &= ~termios.OPOST
            attrs[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, size)
            if self._revoked():
                raise PermissionError('PTY start revoked')
            self.process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                close_fds=True, pass_fds=(workspace_fd, cwd_fd), start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TERM': 'xterm-256color'})
            os.set_blocking(self.master, False)
        except BaseException:
            self.close('unknown')
            raise
        finally:
            if slave >= 0:
                os.close(slave)

    def _revoked(self):
        value = self.revoked()
        if type(value) is not bool:
            raise ValueError('Invalid PTY revocation state')
        return value

    def _check(self):
        if self.closed:
            raise ValueError('PTY closed')
        try:
            stopped = self._revoked()
        except BaseException:
            self.close('revoked')
            raise
        if stopped or time.monotonic() >= self.deadline:
            self.close('revoked' if stopped else 'timed-out')
            raise PermissionError('PTY authority no longer live')

    def write(self, data):
        if (not isinstance(data, bytes) or not 1 <= len(data) <= 4096
                or self.input_bytes + len(data) > INPUT_LIMIT):
            raise ValueError('PTY input quota exceeded')
        self._check()
        # Charge the whole attempt before the syscall. A partial/error outcome
        # consumes its budget and must never cause an implicit replay.
        self.input_bytes += len(data)
        return os.write(self.master, data)

    def resize(self, rows, columns):
        size = geometry(rows, columns)
        self._check()
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, size)

    def read(self, maximum=4096):
        if type(maximum) is not int or not 1 <= maximum <= 4096:
            raise ValueError('Invalid bounded PTY read')
        self._check()
        try:
            data = os.read(self.master, min(maximum, STREAM_LIMIT + 1 - self.output_bytes))
        except BlockingIOError:
            return b''
        except OSError as error:
            if error.errno != errno.EIO:
                self.close('unknown')
                raise
            data = b''  # Linux PTY EIO after the final slave closes; not alone an exit proof.
        self.output_bytes += len(data)
        if self.output_bytes > STREAM_LIMIT:
            self.close('output-limit')
            raise OverflowError('PTY output quota exceeded')
        return data

    def poll(self):
        self._check()
        self.return_code = self.process.poll()
        if self.return_code is not None:
            self.reason = 'exited'  # Callers must still drain the remaining bounded output.
        return self.return_code

    def close(self, reason=None):
        if self.closed:
            return
        self.closed = True
        if reason is not None:
            self.reason = reason
        elif self.reason == 'running':
            self.reason = 'closed'
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.return_code = self.process.wait(timeout=5)
        finally:
            if self.master >= 0:
                os.close(self.master)
                self.master = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
