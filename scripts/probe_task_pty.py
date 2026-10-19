"""Task-owned PTY/kernel guard contracts, only in the disposable Debian guest."""

import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path

from mano_broker.pty_session import TaskPTY
from mano_broker.sandbox import command


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workspace', type=Path)
    parser.add_argument('--foreign', action='store_true')
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() != 0
    assert Path('/etc/mano-lab-disposable').read_text().strip() == 'mano-phase0-ci'
    workspace = os.open(args.workspace, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    cwd = os.open('.', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=workspace)
    try:
        if args.foreign:
            assert os.fstat(0).st_uid != os.geteuid()
            return subprocess.run(command(workspace, cwd, ['/usr/bin/true'], task_pty=True),
                pass_fds=(workspace, cwd), check=False, timeout=10).returncode
        if args.freeze:
            with TaskPTY(workspace, cwd, ['/usr/bin/python3', '-u', '-c',
                    "import os,time;print('READY',flush=True);time.sleep(180)"],
                    timeout=180, revoked=lambda: False) as worker:
                wait(worker, b'READY')
                (args.workspace / 'pty-fixture-ready').write_text(str(worker.process.pid))
                os.kill(os.getpid(), signal.SIGSTOP)
                raise AssertionError('Frozen PTY fixture must be killed by native Stop')
        program = """import os,json,socket,errno
from pathlib import Path
assert all(os.isatty(fd) for fd in (0,1,2))
assert os.tcgetsid(0)==os.getsid(0)
assert os.environ['TERM']=='xterm-256color'
assert not any(key in os.environ for key in (
 'DISPLAY','WAYLAND_DISPLAY','SWAYSOCK','DBUS_SESSION_BUS_ADDRESS','SSH_AUTH_SOCK'))
assert not any(Path(p).exists() for p in ('/dev/input','/dev/uinput','/run/mano-human'))
try:Path('/etc/pty-denial-canary').write_text('forbidden')
except PermissionError:pass
else:raise AssertionError('Protected write succeeded')
try:socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except OSError as error:assert error.errno in (errno.EPERM,errno.EAFNOSUPPORT)
else:raise AssertionError('Network socket succeeded')
with open('/dev/tty') as tty: assert os.isatty(tty.fileno())
print('READY:'+json.dumps(list(os.get_terminal_size())),flush=True)
while True:
 try:line=input()
 except EOFError: print('EOF',flush=True);break
 if line=='size':print('SIZE:'+json.dumps(list(os.get_terminal_size())),flush=True)
 else: print('ECHO:'+line,flush=True)
"""
        with TaskPTY(workspace, cwd, ['/usr/bin/python3', '-u', '-c', program],
                     timeout=15, revoked=lambda: False) as worker:
            initial = wait(worker, b'READY:')
            assert b'[80, 24]' in initial, initial
            assert worker.write(b'hello\n') == 6
            echoed = wait(worker, b'ECHO:hello')
            assert echoed.count(b'hello') == 1
            worker.resize(30, 100)
            worker.write(b'size\n')
            assert b'[100, 30]' in wait(worker, b'SIZE:')
            worker.write(b'\x04')
            wait(worker, b'EOF')
            deadline = time.monotonic() + 3
            while worker.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert worker.return_code == 0
        interrupt = """print('READY',flush=True)
try:input()
except KeyboardInterrupt:print('INTERRUPTED',flush=True)
"""
        with TaskPTY(workspace, cwd, ['/usr/bin/python3', '-u', '-c', interrupt],
                     timeout=10, revoked=lambda: False) as worker:
            wait(worker, b'READY')
            worker.write(b'\x03')
            wait(worker, b'INTERRUPTED')
        revoked = [False]
        worker = TaskPTY(workspace, cwd, ['/usr/bin/python3', '-c', 'import time;time.sleep(60)'],
                         timeout=10, revoked=lambda: revoked[0])
        revoked[0] = True
        try:
            worker.poll()
        except PermissionError:
            assert worker.closed and worker.reason == 'revoked' and worker.return_code is not None
        else:
            raise AssertionError('Revocation was ignored')
        with TaskPTY(workspace, cwd, ['/usr/bin/python3', '-c', 'import time;time.sleep(60)'],
                     timeout=2, revoked=lambda: False) as worker:
            try:
                while True:
                    worker.poll()
                    time.sleep(0.02)
            except PermissionError:
                assert worker.reason == 'timed-out'
        with TaskPTY(workspace, cwd, ['/usr/bin/python3', '-c',
                "import os;os.write(1,b'x'*131072)"], timeout=10, revoked=lambda: False) as worker:
            try:
                while True:
                    worker.read()
                    time.sleep(0.01)
            except OverflowError:
                assert worker.closed and worker.reason == 'output-limit'
        denied = subprocess.run(command(workspace, cwd, ['/usr/bin/true'], task_pty=True),
            stdin=subprocess.DEVNULL, capture_output=True, pass_fds=(workspace, cwd), timeout=10)
        assert denied.returncode == 125 and b'guard task-owned PTY' in denied.stderr, denied.stderr
        print(json.dumps(dict(task_owned_controlling_pty=True, interactive_echo_resize_eof=True,
            foreground_interrupt=True, protected_write_network_and_human_ipc_denied=True,
            timeout_revocation_and_output_limit=True, pipes_not_accepted_as_pty=True,
            public_broker_session_implemented=False, physical_input_provenance=None)))
        return 0
    finally:
        os.close(cwd)
        os.close(workspace)


def wait(worker, marker):
    deadline, data = time.monotonic() + 8, bytearray()
    while time.monotonic() < deadline:
        data.extend(worker.read())
        if marker in data:
            # The line may span separate reads; require its terminating newline.
            start = data.index(marker)
            if b'\n' in data[start:]:
                return bytes(data)
        time.sleep(0.01)
    raise AssertionError('PTY marker not observed: ' + repr(bytes(data[-1024:])))


if __name__ == '__main__':
    raise SystemExit(main())
