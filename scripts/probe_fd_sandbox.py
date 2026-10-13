#!/usr/bin/env python3
"""Disposable operator-driven FD sandbox test, not broker/model execution."""

import grp
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from mano_broker.identities import LOCK, allocate_identity
from mano_broker.runner import OUTPUT_LIMIT, run
from mano_broker.sandbox import GUARD, command
from mano_broker.workspaces import BASE, create_workspace

ROOT = Path("/opt/mano-lab")
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
if len(sys.argv) == 1:
    assert (
        subprocess.run(
            ["systemctl", "is-active", "mano-fd-sandbox-ci.scope"], capture_output=True
        ).returncode
        != 0
    )
    subprocess.run(
        [
            "systemd-run",
            "--quiet",
            "--scope",
            "--collect",
            "--unit=mano-fd-sandbox-ci",
            "--property=MemoryMax=128M",
            "--property=TasksMax=24",
            "--property=CPUQuota=20%",
            "--",
            "/usr/bin/env",
            "PYTHONPATH=/opt/mano-lab/src",
            "/usr/bin/python3",
            str(Path(__file__).absolute()),
            "--bounded",
        ],
        check=True,
        timeout=90,
    )
    sys.exit(0)
assert sys.argv[1:] == ["--bounded"]
assert "mano-fd-sandbox-ci.scope" in Path("/proc/self/cgroup").read_text()
assert not BASE.exists() and not LOCK.exists()
assert "mano-broker" not in {p.pw_name for p in pwd.getpwall()}
assert "mano-request" not in {g.gr_name for g in grp.getgrall()}
code = Path("/usr/lib/mano-os")
assert not code.exists() and not GUARD.exists()
created = []
group_created = False
fds = []
server = None
child = None
try:
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
            "/opt/mano-lab/native/mano_sandbox_guard.c",
            "-lseccomp",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(GUARD),
        ],
        check=True,
    )
    GUARD.chmod(0o555)
    limits = {
        prop: subprocess.check_output(
            ["systemctl", "show", "mano-fd-sandbox-ci.scope", f"--property={prop}", "--value"],
            text=True,
        ).strip()
        for prop in ("MemoryMax", "TasksMax", "CPUQuotaPerSecUSec")
    }
    assert limits == {"MemoryMax": "134217728", "TasksMax": "24", "CPUQuotaPerSecUSec": "200ms"}
    subprocess.run(["groupadd", "mano-request"], check=True)
    group_created = True
    subprocess.run(["useradd", "--system", "--no-create-home", "mano-broker"], check=True)
    created.append("mano-broker")
    identity = allocate_identity()
    created.append(identity.name)
    workspace, fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    fds.append(fd)
    cwd = os.dup(fd)
    fds.append(cwd)
    inode = os.fstat(fd).st_ino
    moved = workspace.with_name(workspace.name + "-moved")
    workspace.rename(moved)
    workspace.symlink_to("/etc", target_is_directory=True)
    code.mkdir(mode=0o755)
    protected = Path("/etc/mano-lab-disposable")
    before = hashlib.sha256(protected.read_bytes()).hexdigest()
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    socket_inode = os.fstat(server.fileno()).st_ino
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        try:
            os.setgroups([grp.getgrnam("mano-request").gr_gid])
            os.setgid(identity.gid)
            os.setuid(identity.uid)
            assert "mano-fd-sandbox-ci.scope" in Path("/proc/self/cgroup").read_text()
            payload = """import ctypes,errno,json,os,socket,subprocess,sys
from pathlib import Path
assert Path('/workspace').stat().st_ino==int(sys.argv[1])
assert Path.cwd().stat().st_ino==int(sys.argv[1])
assert dict(os.environ)=={'PATH':'/usr/bin:/bin','HOME':'/home/task',
 'LANG':'C.UTF-8','PWD':'/task-cwd'}
assert not Path('/run/mano-broker').exists()
assert not Path('/etc/mano-lab-disposable').exists()
assert not Path('/usr/lib/mano-os/mano_broker').exists()
assert not Path('/usr/lib/mano-broker/libmano-resources.so').exists()
assert not Path('/usr/libexec/mano-approve').exists()
for p in ('/dev/input','/dev/uinput','/var/lib/mano-broker','/run/user'):
 assert not Path(p).exists(),p
for entry in Path('/proc/self/fd').iterdir():
 try:info=entry.stat()
 except FileNotFoundError:continue
 assert info.st_ino!=int(sys.argv[3]),'inherited host socket'
try:Path('/usr/share/mano-forbidden-ci').write_text('blocked')
except OSError as e:assert e.errno in (errno.EROFS,errno.EACCES,errno.ENOENT)
else:raise AssertionError('OS tree writable')
try:
 s=socket.socket();s.settimeout(1);s.connect(('127.0.0.1',int(sys.argv[2])))
except OSError as e:assert e.errno==errno.EPERM
else:raise AssertionError('host network reachable')
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
assert status['NoNewPrivs'].strip()=='1'
assert status['CapEff'].strip()=='0000000000000000'
assert status['Seccomp'].strip()=='2'
libc=ctypes.CDLL(None,use_errno=True)
assert libc.unshare(0)==-1 and ctypes.get_errno()==errno.EPERM
assert libc.setresuid(-1,-1,-1)==-1 and ctypes.get_errno()==errno.EPERM
try:Path('/etc/landlock-task-denial').write_text('blocked')
except OSError as e:assert e.errno==errno.EACCES
else:raise AssertionError('Landlock write escape')
project=chr(10).join([
 'import ctypes,errno',
 'from pathlib import Path',
 'libc=ctypes.CDLL(None,use_errno=True)',
 'assert libc.unshare(0)==-1 and ctypes.get_errno()==errno.EPERM',
 "try:Path('/etc/child-landlock-denial').write_text('blocked')",
 'except OSError as e:assert e.errno==errno.EACCES',
 "else:raise AssertionError('child Landlock inheritance missing')",
 'print(42)',
])+chr(10)
Path('/workspace/project.py').write_text(project)
result=subprocess.run(['/usr/bin/python3','/workspace/project.py'],capture_output=True,text=True)
assert result.returncode==0 and result.stdout.strip()=='42',result.stderr
print(json.dumps({'workspace_fd_identity':True,'cwd_fd_identity':True,
 'host_network_denied':True,'host_ipc_absent':True,'inherited_socket_absent':True,
 'minimal_environment':True,'os_tree_readonly':True,'no_new_privs':True,'capabilities_zero':True,
 'seccomp_no_change_syscalls_denied':True,'landlock_private_etc_write_denied':True,
 'subprocess_execution_and_inheritance':True}))
"""
            args = command(
                fd,
                cwd,
                ["/usr/bin/python3", "-c", payload, str(inode), str(port), str(socket_inode)],
            )
            result = subprocess.run(
                args,
                pass_fds=(fd, cwd),
                close_fds=True,
                stdin=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "HOST_SECRET_CANARY": "synthetic-not-a-secret"},
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert result.returncode == 0, result.stderr
            proof = json.loads(result.stdout)
            cgroup = (
                Path("/sys/fs/cgroup")
                / Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1].lstrip("/")
                / "cgroup.procs"
            )
            # These two fixture controllers remain alive until every task test
            # finishes. An arbitrary snapshot can include a prior bwrap child
            # that exits a moment later, which must not become a permanent PID.
            baseline = {str(os.getpid()), str(os.getppid())}

            def reaped():
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    current = set(cgroup.read_text().split())
                    if current == baseline:
                        return
                    time.sleep(0.05)
                details = {}
                for pid in current | baseline:
                    try:
                        lines = Path(f"/proc/{pid}/status").read_text().splitlines()
                        details[pid] = [
                            line
                            for line in lines
                            if line.startswith(("Name:", "State:", "Pid:", "PPid:", "Uid:"))
                        ]
                    except (FileNotFoundError, ProcessLookupError):
                        details[pid] = "reaped"
                raise AssertionError(
                    dict(
                        message="Cgroup baseline not restored",
                        baseline=sorted(baseline),
                        current=sorted(current),
                        removed=sorted(baseline - current),
                        added=sorted(current - baseline),
                        processes=details,
                    )
                )

            reaped()  # Prior manual sandbox must also leave no extra processes.
            gate_reader, gate_writer = os.pipe()
            transient = os.fork()
            if transient == 0:
                os.close(gate_writer)
                os.read(gate_reader, 1)
                os._exit(0)
            os.close(gate_reader)
            try:
                sampled = set(cgroup.read_text().split())
                assert baseline <= sampled and str(transient) in sampled
                os.write(gate_writer, b"x")
                os.close(gate_writer)
                gate_writer = -1
                reaped()
                _, transient_status = os.waitpid(transient, 0)
                assert os.waitstatus_to_exitcode(transient_status) == 0
            finally:
                if gate_writer >= 0:
                    os.close(gate_writer)
            proof["known_controller_baseline"] = True
            proof["transient_pid_sample_does_not_become_baseline"] = True

            def execute(source, timeout=5, observer=lambda: False):
                started = time.monotonic()
                outcome = run(
                    fd, cwd, ["/usr/bin/python3", "-c", source], timeout=timeout, revoked=observer
                )
                assert time.monotonic() - started < 8
                reaped()
                return outcome

            normal = execute("print('bounded-ok')")
            assert normal.reason == "completed" and normal.return_code == 0
            assert normal.stdout.strip() == b"bounded-ok"
            for stream in (1, 2):
                noisy = execute(f"import os;os.write({stream},b'x'*200000)")
                assert noisy.reason == "output-limit"
                assert len(noisy.stdout if stream == 1 else noisy.stderr) == OUTPUT_LIMIT
                assert len(noisy.stdout) <= OUTPUT_LIMIT and len(noisy.stderr) <= OUTPUT_LIMIT
            timed = execute("import os,time;os.fork();time.sleep(60)", timeout=1)
            assert timed.reason == "timed-out"
            eof = execute("import os,time;os.close(1);os.close(2);time.sleep(60)", timeout=1)
            assert eof.reason == "timed-out"
            revoked = execute(
                "import time;from pathlib import Path;"
                "Path('/workspace/revocation-started').write_text('started');time.sleep(60)",
                observer=lambda: (moved / "revocation-started").exists(),
            )
            assert revoked.reason == "revoked" and revoked.return_code is not None
            before_start = execute(
                "from pathlib import Path;Path('/workspace/must-not-start').write_text('bad')",
                observer=lambda: True,
            )
            assert before_start.reason == "revoked" and before_start.return_code is None
            assert not (moved / "must-not-start").exists()
            proof["bounded_runner"] = dict(
                normal_command=True,
                stdout_limit=OUTPUT_LIMIT,
                stderr_limit=OUTPUT_LIMIT,
                fork_timeout_reaped=True,
                closed_pipes_deadline=True,
                active_revocation_reaped=True,
                revoked_before_start_no_effect=True,
                baseline_cgroup_restored=True,
            )
            os.write(writer, json.dumps(proof).encode())
            os._exit(0)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(writer)
    _, status = os.waitpid(child, 0)
    child = None
    assert os.waitstatus_to_exitcode(status) == 0
    observed = json.loads(os.read(reader, 65536))
    os.close(reader)
    assert hashlib.sha256(protected.read_bytes()).hexdigest() == before
    assert "child Landlock inheritance missing" in (moved / "project.py").read_text()
    print(
        json.dumps(
            dict(
                scope="fixed FD sandbox under operator CI cgroup; broker executor not integrated",
                observations=observed,
                source_name_replaced_with_symlink=True,
                protected_host_hash_unchanged=True,
                workspace_output_verified=True,
                cgroup_limits=limits,
                current_process_and_task_in_scope=True,
                seccomp_profile_enforced=True,
                landlock_enforced=True,
                native_guard_sha256=hashlib.sha256(GUARD.read_bytes()).hexdigest(),
                model_connected=False,
                production_execution_authorized=False,
            ),
            indent=2,
        )
    )
finally:
    if child:
        os.kill(child, 9)
        os.waitpid(child, 0)
    if server:
        server.close()
    for fd in fds:
        os.close(fd)
    if BASE.exists():
        shutil.rmtree(BASE)
    if code.exists():
        code.rmdir()
    GUARD.unlink(missing_ok=True)
    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
    if group_created:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)
