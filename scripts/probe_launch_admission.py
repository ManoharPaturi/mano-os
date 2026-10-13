#!/usr/bin/env python3
"""Kernel peer/FD launch admission only; no root execution endpoint or effects."""

import json
import os
import pwd
import shutil
import socket
import subprocess
from pathlib import Path

from mano_broker.identities import LOCK, allocate_identity
from mano_broker.launch_admission import receive
from mano_broker.protocol import canonical
from mano_broker.resources import LIBRARY
from mano_broker.workspaces import BASE, create_workspace

assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not BASE.exists() and not LOCK.exists() and not LIBRARY.exists()
created = []
group = False
listener = None
server = None
fd = None
try:
    subprocess.run(["groupadd", "mano-request"], check=True)
    group = True
    subprocess.run(["useradd", "--system", "--no-create-home", "mano-broker"], check=True)
    created.append("mano-broker")
    identity = allocate_identity()
    created.append(identity.name)
    work, fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    os.close(fd)
    fd = None
    world = BASE / "world"
    world.mkdir()
    os.chown(world, pwd.getpwnam("mano-broker").pw_uid, identity.gid)
    world.chmod(0o777)
    LIBRARY.parent.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-shared",
            "/opt/mano-lab/native/mano_resources.c",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(LIBRARY),
        ],
        check=True,
    )
    LIBRARY.chmod(0o644)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    listener.bind(str(BASE / "admission.sock"))
    (BASE / "admission.sock").chmod(0o666)  # Exercise protocol, not DAC, for hostile actors.
    listener.listen(16)
    listener.settimeout(15)
    reader, writer = os.pipe()
    server = os.fork()
    if server == 0:
        os.close(reader)
        try:
            accepted = 0
            for _ in range(14):
                before = len(list(Path("/proc/self/fd").iterdir()))
                connection, _ = listener.accept()
                with connection:
                    try:
                        admission = receive(connection)
                    except (
                        ValueError,
                        TypeError,
                        KeyError,
                        OSError,
                        RecursionError,
                        subprocess.SubprocessError,
                    ):
                        result = {"ok": False}
                    else:
                        assert admission.caller_uid == identity.uid
                        admission.close()
                        accepted += 1
                        result = {"ok": True}
                    connection.sendall(canonical(result).encode())
                assert len(list(Path("/proc/self/fd").iterdir())) == before
            assert accepted == 1
            os.write(writer, b'{"no_descriptor_leak":true,"accepted_count":1}')
            os._exit(0)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(writer)
    listener.close()
    listener = None
    request = dict(
        schema_version="1.0",
        task_id="a" * 32,
        grant_id="b" * 32,
        capability="terminal.run",
        resource_id="c" * 32,
        args=dict(argv=["/usr/bin/true"], cwd=".", timeout_seconds=5),
        idempotency_key="d" * 32,
        reason="trusted fixture metadata only",
    )
    body = dict(action_id="e" * 32, caller_uid=identity.uid, request=request)
    client = """import array,json,os,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5);s.connect(sys.argv[1])
packet=sys.stdin.buffer.read();paths=json.loads(sys.argv[2]);flags=int(sys.argv[3])
fds=[os.open(p,flags|os.O_CLOEXEC) for p in paths]
def send():
 s.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else [])
 print(s.recv(65536).decode())
if sys.argv[4]=='handoff':
 pid=os.fork()
 if pid==0:send();os._exit(0)
 _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0
else:send()
"""
    cases = []

    def exchange(name, paths, *, actor="mano-broker", value=body, flags=os.O_PATH, handoff=False):
        envelope = dict(schema_version="1.0", operation="launch_task", body=value)
        result = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                actor,
                "--",
                "python3",
                "-u",
                "-c",
                client,
                str(BASE / "admission.sock"),
                json.dumps(list(map(str, paths))),
                str(flags),
                "handoff" if handoff else "normal",
            ],
            input=canonical(envelope),
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        assert json.loads(result.stdout) == {"ok": name == "valid"}, (name, result.stderr)
        cases.append(dict(case=name, denied=name != "valid"))

    exchange("valid", [work, work])
    exchange("no-fd", [])
    exchange("multiple-fds", [work, work, work])
    exchange("non-O_PATH", [work, work], flags=os.O_RDONLY)
    exchange("wrong-cwd", [work, Path("/tmp")])
    exchange("extra-env", [work, work], value=body | {"env": {"HOST": "forbidden"}})
    exchange(
        "non-terminal",
        [work, work],
        value=body | {"request": request | {"capability": "system.inspect_health", "args": {}}},
    )
    exchange("root-uid", [work, work], value=body | {"caller_uid": 0})
    exchange("world-workspace", [world, world])
    for actor in ("root", "mano-human", "mano-worker", "mano-core"):
        exchange("actor-" + actor, [Path("/tmp"), Path("/tmp")], actor=actor)
    exchange("inherited-broker-connection", [work, work], handoff=True)
    _, status = os.waitpid(server, 0)
    server = None
    assert os.waitstatus_to_exitcode(status) == 0
    observed = json.loads(os.read(reader, 65536))
    os.close(reader)
    print(
        json.dumps(
            dict(
                scope="private launch admission library only; no installed root execution service",
                observations=observed,
                cases=cases,
                real_root_receiver=True,
                kernel_broker_peer_and_message_credentials=True,
                cwd_inode_binding=True,
                restricted_task_identity=True,
                no_operation_executed=True,
                model_connected=False,
            ),
            indent=2,
        )
    )
finally:
    if listener:
        listener.close()
    if server:
        os.kill(server, 9)
        os.waitpid(server, 0)
    if fd is not None:
        os.close(fd)
    LIBRARY.unlink(missing_ok=True)
    if BASE.exists():
        shutil.rmtree(BASE)
    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
    if group:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)
