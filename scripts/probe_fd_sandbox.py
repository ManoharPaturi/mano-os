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
from pathlib import Path

from mano_broker.identities import LOCK, allocate_identity
from mano_broker.sandbox import command
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
assert not BASE.exists() and not LOCK.exists()
assert "mano-broker" not in {p.pw_name for p in pwd.getpwall()}
assert "mano-request" not in {g.gr_name for g in grp.getgrall()}
code = Path("/usr/lib/mano-os")
assert not code.exists()
created = []
group_created = False
fds = []
server = None
child = None
try:
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
            payload = """import errno,json,os,socket,sys
from pathlib import Path
assert Path('/workspace').stat().st_ino==int(sys.argv[1])
assert Path.cwd().stat().st_ino==int(sys.argv[1])
assert set(os.environ)=={'PATH','HOME','LANG'}
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
s=socket.socket();s.settimeout(1)
try:s.connect(('127.0.0.1',int(sys.argv[2])))
except OSError as e:assert e.errno in (errno.ECONNREFUSED,errno.ENETUNREACH)
else:raise AssertionError('host network reachable')
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
assert status['NoNewPrivs'].strip()=='1'
assert status['CapEff'].strip()=='0000000000000000'
Path('/workspace/project.py').write_text('print(42)'+chr(10))
print(json.dumps({'workspace_fd_identity':True,'cwd_fd_identity':True,
 'host_network_denied':True,'host_ipc_absent':True,'inherited_socket_absent':True,
 'minimal_environment':True,'os_tree_readonly':True,'no_new_privs':True,'capabilities_zero':True}))
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
            os.write(writer, result.stdout.encode())
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
    assert (moved / "project.py").read_text() == "print(42)" + chr(10)
    print(
        json.dumps(
            dict(
                scope="fixed FD sandbox under operator CI cgroup; broker executor not integrated",
                observations=observed,
                source_name_replaced_with_symlink=True,
                protected_host_hash_unchanged=True,
                workspace_output_verified=True,
                cgroup_limits=limits,
                seccomp_profile_enforced=None,
                landlock_enforced=None,
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
    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
    if group_created:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)
