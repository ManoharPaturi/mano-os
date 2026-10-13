#!/usr/bin/env python3
"""Real root FD passing to an unprivileged receiver, disposable VM only."""

import array
import json
import os
import pwd
import shutil
import socket
import subprocess
from pathlib import Path

from mano_broker.protocol import canonical
from mano_broker.provision import serve_provision
from mano_broker.registry import Registry
from mano_broker.resources import LIBRARY
from mano_broker.state import State

BASE = Path("/run/mano-provision-ci")
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not BASE.exists() and not LIBRARY.exists()
subprocess.run(
    [
        "useradd",
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "mano-provision-ci",
    ],
    check=True,
)
account = pwd.getpwnam("mano-provision-ci")
listener = None
server = None
try:
    BASE.mkdir(mode=0o755)
    state_dir = BASE / "state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, account.pw_uid, account.pw_gid)
    work = BASE / "workspace"
    work.mkdir()
    os.chown(work, account.pw_uid, 1004)
    work.chmod(0o2770)
    public = BASE / "public"
    public.mkdir()
    os.chown(public, account.pw_uid, 1004)
    public.chmod(0o777)
    wrong = BASE / "wrong-owner"
    wrong.mkdir(mode=0o770)
    os.chown(wrong, 0, 1004)
    wrong.chmod(0o770)
    wrong_group = BASE / "wrong-group"
    wrong_group.mkdir()
    os.chown(wrong_group, account.pw_uid, account.pw_gid)
    wrong_group.chmod(0o770)
    regular = BASE / "regular"
    regular.write_text("not-directory")
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
    listener.bind(str(BASE / "provision.sock"))
    (BASE / "provision.sock").chmod(0o666)
    listener.listen(16)
    listener.settimeout(15)
    reader, writer = os.pipe()
    server = os.fork()
    if server == 0:
        os.close(reader)
        try:
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            state = State(state_dir)
            registry = Registry()
            observations = []
            for _ in range(12):
                before = len(list(Path("/proc/self/fd").iterdir()))
                resources = len(registry.resources)
                connection, _ = listener.accept()
                with connection:
                    serve_provision(
                        state,
                        registry,
                        connection,
                        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    )
                after = len(list(Path("/proc/self/fd").iterdir()))
                added = len(registry.resources) - resources
                assert after == before + added, "descriptor leak"
                observations.append({"new_resources": added, "descriptor_delta": after - before})
            assert len(registry.resources) == 1
            assert state.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 1
            registry.close()
            state.close()
            os.write(
                writer,
                canonical({"broker_uid": os.geteuid(), "observations": observations}).encode(),
            )
            os._exit(0)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(writer)
    listener.close()
    listener = None
    body = dict(human_uid=1002, caller_uid=1004, mode="supervised", classification="internal")
    packet = canonical(dict(schema_version="1.0", operation="provision_task", body=body)).encode()
    denied = {"schema_version": "1.0", "ok": False, "error": "denied"}
    cases = []

    def exchange(name, paths, payload=packet, flags=os.O_PATH, actor=None, handoff=False):
        if actor:
            source = """import json,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5);s.connect(sys.argv[1])
s.sendall(b'{}');print(s.recv(65536).decode())
"""
            result = subprocess.run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    actor,
                    "--",
                    "python3",
                    "-c",
                    source,
                    str(BASE / "provision.sock"),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            response = json.loads(result.stdout)
        else:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            client.settimeout(5)
            client.connect(str(BASE / "provision.sock"))
            fds = [os.open(path, flags | os.O_CLOEXEC) for path in paths]

            def send():
                ancillary = (
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
                )
                client.sendmsg([payload], ancillary)
                return json.loads(client.recv(65536))

            try:
                if handoff:
                    child = os.fork()
                    if child == 0:
                        try:
                            assert send() == denied
                            os._exit(0)
                        except BaseException:
                            os._exit(1)
                    _, status = os.waitpid(child, 0)
                    assert os.waitstatus_to_exitcode(status) == 0
                    response = denied
                else:
                    response = send()
            finally:
                for fd in fds:
                    os.close(fd)
                client.close()
        if name == "valid":
            assert response["ok"] and set(response) == {
                "schema_version",
                "ok",
                "task_id",
                "resource_id",
            }
        else:
            assert response == denied, (name, response)
        cases.append({"case": name, "denied": name != "valid"})

    exchange("valid", [work])
    exchange("no-fd", [])
    exchange("multiple-fds", [work, work])
    exchange("regular-file", [regular])
    exchange("non-O_PATH", [work], flags=os.O_RDONLY)
    exchange("world-accessible", [public])
    exchange("wrong-owner", [wrong])
    exchange("wrong-group", [wrong_group])
    exchange(
        "injected-path",
        [work],
        canonical(
            dict(schema_version="1.0", operation="provision_task", body=body | {"path": "/etc"})
        ).encode(),
    )
    exchange(
        "invalid-mode-cleanup",
        [work],
        canonical(
            dict(schema_version="1.0", operation="provision_task", body=body | {"mode": "invalid"})
        ).encode(),
    )
    exchange("unprivileged-sender", [], actor="mano-worker")
    exchange("inherited-root-connection", [work], handoff=True)
    response = os.read(reader, 65536)
    os.close(reader)
    _, status = os.waitpid(server, 0)
    server = None
    assert os.waitstatus_to_exitcode(status) == 0
    data = json.loads(response)
    print(
        json.dumps(
            dict(
                scope="provisioning receiver library; daemon not wired",
                broker_uid=data["broker_uid"],
                root_descriptor_provisioned=True,
                cases=cases,
                descriptor_deltas=data["observations"],
                no_descriptor_leak=True,
                one_task_only=True,
                model_connected=False,
                no_operation_executed=True,
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
    LIBRARY.unlink(missing_ok=True)
    shutil.rmtree(BASE)
    subprocess.run(["userdel", "mano-provision-ci"], check=False, capture_output=True)
