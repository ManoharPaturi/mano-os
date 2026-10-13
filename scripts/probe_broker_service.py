#!/usr/bin/env python3
"""Actual provision/PAM/descriptor preparation service flow in disposable Debian."""

import base64
import hashlib
import json
import os
import pwd
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mano_broker.identities import LOCK, allocate_identity
from mano_broker.sandbox import GUARD
from mano_broker.workspaces import BASE, create_workspace

ROOT = Path("/opt/mano-lab")
STATE = Path("/var/lib/mano-broker/runtime")
CODE = Path("/usr/lib/mano-os")
WORK = Path("/run/mano-live-workspace-ci")
LIBRARY = Path("/usr/lib/mano-broker/libmano-resources.so")
NATIVE = Path("/usr/libexec/mano-approve")
STOP_NATIVE = Path("/usr/libexec/mano-stopd")
STOP_STATE = Path("/var/lib/mano-stopd")
POLICY = Path("/etc/mano/human.uid")
PAM = Path("/etc/pam.d/mano-approve")
SOCKETS = {
    name: Path("/run/mano-broker") / (name + ".sock")
    for name in ("request", "control", "provision")
}
UNITS = (
    "mano-broker.service",
    "mano-broker.socket",
    "mano-broker-control.socket",
    "mano-broker-provision.socket",
    "mano-approve.service",
    "mano-approve.socket",
    "mano-launcher.service",
    "mano-launcher-prepare.socket",
    "mano-launcher-control.socket",
    "mano-stopd.service",
    "mano-stopd.socket",
    "mano-stopd-control.socket",
)
assert (
    os.geteuid() == 0 and Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
)
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert all(
    not p.exists() for p in (STATE, CODE, WORK, LIBRARY, NATIVE, POLICY, PAM, GUARD, BASE,
                           LOCK, STOP_NATIVE, STOP_STATE, *SOCKETS.values())
)
assert all(not (Path("/etc/systemd/system") / u).exists() for u in UNITS)
old_mode = STATE.parent.stat().st_mode & 0o777
installed = []
created_user = False
created_group = False
joined = False
identity = None


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def ready(previous=None):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        pid = int(
            command("systemctl", "show", "mano-broker.service", "--property=MainPID", "--value")
        )
        status = command(
            "systemctl", "show", "mano-broker.service", "--property=ActiveState", "--value"
        )
        if pid and pid != previous and status == "active":
            return pid
        time.sleep(0.2)
    raise AssertionError("Broker service not ready")


client = """import array,errno,json,os,socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5)
s.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
try:s.connect(sys.argv[1])
except PermissionError as e:
 assert e.errno==errno.EACCES;print(json.dumps({'kernel_errno':'EACCES'}));sys.exit(0)
_,creator,_=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert creator==0
packet=sys.stdin.buffer.read()
if sys.argv[3]!='-':
 fd=os.open(sys.argv[3],os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
 s.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]);os.close(fd)
else:s.sendall(packet)
reply,ancillary,flags,_=s.recvmsg(131072,socket.CMSG_SPACE(12))
assert not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)
assert len(ancillary)==1 and ancillary[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS)
pid,uid,_=struct.unpack('3i',ancillary[0][2]);assert uid==int(sys.argv[2])
print(json.dumps({'payload':json.loads(reply),'sender_pid':pid,'sender_uid':uid,'creator_uid':creator}))
"""


def rpc(channel, body, actor="mano-worker", directory=None):
    result = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            actor,
            "--",
            "python3",
            "-c",
            client,
            str(SOCKETS[channel]),
            str(broker_uid),
            str(directory) if directory else "-",
        ],
        input=json.dumps(body),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    decoded = json.loads(result.stdout)
    if "kernel_errno" in decoded:
        return decoded
    actual_pid = int(
        command("systemctl", "show", "mano-broker.service", "--property=MainPID", "--value")
    )
    assert decoded["sender_pid"] == actual_pid and decoded["sender_uid"] == broker_uid
    assert decoded["creator_uid"] == 0
    return decoded["payload"]


native_client = """import json,sys
from mano_prompt.approve import (rpc,view_packet,confirmation_packet,
 rearm_view_packet,rearm_confirmation_packet)
body=json.loads(sys.stdin.read())
try:
 if body['mode']=='view':result=rpc(view_packet(body['id']))
 elif body['mode']=='rearm_view':result=rpc(rearm_view_packet())
 elif body['mode']=='rearm_confirm':
  result=rpc(rearm_confirmation_packet(body['view'],body['password']))
 else:result=rpc(confirmation_packet(body['view'],body['password']))
except (PermissionError,ValueError):result={'ok':False}
print(json.dumps(result))
"""


def human(body, actor="mano-human"):
    result = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            actor,
            "--",
            "env",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "python3",
            "-c",
            native_client,
        ],
        input=json.dumps(body),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


try:
    subprocess.run(["groupadd", "mano-request"], check=True)
    created_group = True
    subprocess.run(
        ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "mano-broker"],
        check=True,
    )
    created_user = True
    account = pwd.getpwnam("mano-broker")
    broker_uid = account.pw_uid
    assert broker_uid not in {0, 1001, 1002, 1003, 1004}
    subprocess.run(["usermod", "-a", "-G", "mano-request", "mano-worker"], check=True)
    joined = True
    CODE.mkdir(mode=0o755)
    for package in ("mano_broker", "mano_prompt", "mano_lab"):
        shutil.copytree(
            ROOT / "src" / package, CODE / package, ignore=shutil.ignore_patterns("__pycache__")
        )
        for file in (CODE / package).rglob("*.py"):
            file.chmod(0o444)
        (CODE / package).chmod(0o555)
    GUARD.parent.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
        str(ROOT / "native/mano_sandbox_guard.c"), "-lseccomp", "-Wl,-z,relro,-z,now",
        "-o", str(GUARD)], check=True)
    GUARD.chmod(0o555)
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", str(ROOT / "native/mano_stopd.c"),
        *command("pkg-config", "--cflags", "--libs", "libsystemd").split(),
        "-Wl,-z,relro,-z,now", "-o", str(STOP_NATIVE)], check=True)
    STOP_NATIVE.chmod(0o555)
    LIBRARY.parent.mkdir(mode=0o755, exist_ok=True)
    NATIVE.parent.mkdir(mode=0o755, exist_ok=True)
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
            str(ROOT / "native/mano_resources.c"),
            "-Wl,-z,relro,-z,now",
            "-o",
            str(LIBRARY),
        ],
        check=True,
    )
    LIBRARY.chmod(0o644)
    flags = command("pkg-config", "--cflags", "--libs", "json-c", "libsystemd").split()
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
            str(ROOT / "native/mano_approve.c"),
            *flags,
            "-lpam",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(NATIVE),
        ],
        check=True,
    )
    NATIVE.chmod(0o755)
    STATE.parent.chmod(0o711)
    WORK.mkdir()
    os.chown(WORK, broker_uid, 1004)
    WORK.chmod(0o2770)
    target = WORK / "file"
    target.write_text("approved-target")
    os.chown(target, broker_uid, 1004)
    target.chmod(0o660)
    POLICY.write_text("1002\n")
    POLICY.chmod(0o600)
    shutil.copyfile(ROOT / "packaging/pam/mano-approve", PAM)
    password = secrets.token_hex(24)
    subprocess.run(
        ["chpasswd"],
        input="mano-human:" + password + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    for unit in UNITS:
        dest = Path("/etc/systemd/system") / unit
        shutil.copyfile(ROOT / "packaging/systemd" / unit, dest)
        installed.append(dest)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(
        [
            "systemctl",
            "start",
            "mano-broker.socket",
            "mano-broker-control.socket",
            "mano-broker-provision.socket",
            "mano-approve.socket",
            "mano-launcher-prepare.socket",
            "mano-launcher-control.socket",
        ],
        check=True,
    )
    envelope = {
        "schema_version": "1.0",
        "operation": "provision_task",
        "body": dict(human_uid=1002, caller_uid=1004, mode="supervised", classification="internal"),
    }
    provision = rpc("provision", envelope, actor="root", directory=WORK)
    assert provision["ok"]
    pid = ready()
    assert "broker-mutation-filters-verified" in command(
        "journalctl", "-u", "mano-broker.service", "--no-pager"
    )
    fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        if ":" in line
    )
    assert set(map(int, fields["Uid"].split())) == {broker_uid}
    assert fields["NoNewPrivs"].strip() == "1" and fields["Seccomp"].strip() == "2"
    assert int(fields["CapEff"].strip(), 16) == 0
    for name, mode in (("request", 0o660), ("control", 0o600), ("provision", 0o600)):
        info = SOCKETS[name].stat()
        assert info.st_uid == 0 and info.st_mode & 0o777 == mode
    assert STATE.stat().st_uid == broker_uid and STATE.stat().st_mode & 0o777 == 0o700
    assert (STATE / "state.sqlite3").stat().st_mode & 0o777 == 0o600
    limits = {
        name: command("systemctl", "show", "mano-broker.service", f"--property={name}", "--value")
        for name in (
            "TasksMax",
            "MemoryMax",
            "CPUQuotaPerSecUSec",
            "LimitNOFILE",
            "ProtectSystem",
            "ProtectHome",
            "PrivateDevices",
            "RestrictNamespaces",
        )
    }
    assert limits["TasksMax"] == "16" and limits["MemoryMax"] == "134217728"
    assert limits["CPUQuotaPerSecUSec"] == "200ms" and limits["LimitNOFILE"] == "128"
    denials = []
    for channel, actors in (
        ("request", ("mano-agent", "mano-core", "mano-human")),
        ("control", ("mano-agent", "mano-core", "mano-worker", "mano-human")),
        ("provision", ("mano-agent", "mano-core", "mano-worker", "mano-human")),
    ):
        for actor in actors:
            assert rpc(
                channel, {"schema_version": "1.0", "operation": "invalid", "body": {}}, actor
            ) == {"kernel_errno": "EACCES"}
            denials.append(
                {"actor": actor, "target": channel + "-socket", "kernel_errno": "EACCES"}
            )
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        result = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                actor,
                "--",
                "python3",
                "-c",
                "import errno;from pathlib import Path\n"
                "try:Path('/var/lib/mano-broker/runtime/state.sqlite3').read_bytes()\n"
                "except PermissionError as e:assert e.errno==errno.EACCES\n"
                "else:raise AssertionError('journal read')",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr
        denials.append({"actor": actor, "target": "private-journal", "kernel_errno": "EACCES"})
    proposal = dict(
        schema_version="1.0",
        task_id=provision["task_id"],
        resource_id=provision["resource_id"],
        capability="files.read",
        args={"path": "file"},
        idempotency_key="read",
        reason="fixed live CI",
    )
    denied = {"schema_version": "1.0", "ok": False, "error": "denied"}
    assert (
        rpc(
            "request",
            dict(
                schema_version="1.0",
                operation="request_approval",
                body=proposal | {"resource_id": "a" * 32},
            ),
        )
        == denied
    )
    pending = rpc(
        "request", dict(schema_version="1.0", operation="request_approval", body=proposal)
    )["approval"]
    assert pending["state"] == "pending" and pending["grant_id"] is None
    assert set(pending) == {"approval_id", "state", "grant_id"}
    query = dict(
        schema_version="1.0",
        operation="approval_status",
        body={"approval_id": pending["approval_id"]},
    )
    assert rpc("request", query)["approval"] == pending
    assert rpc("request", query | {"operation": "approve"}) == denied
    view = human({"mode": "view", "id": pending["approval_id"]})["view"]
    assert view["human_uid"] == 1002
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        assert human({"mode": "view", "id": pending["approval_id"]}, actor) == {"ok": False}
    assert human({"mode": "confirm", "view": view, "password": "wrong-ci-password"}) == {
        "ok": False
    }
    assert rpc("request", query)["approval"]["grant_id"] is None
    assert human({"mode": "confirm", "view": view | {"nonce": "0" * 64}, "password": password}) == {
        "ok": False
    }
    # Keep root control schema/binding negatives without treating root as PAM consent.
    confirm = dict(
        schema_version="1.0",
        operation="confirm_approval",
        body=dict(
            approval_id=view["approval_id"],
            human_uid=1002,
            nonce=view["nonce"],
            operation_digest=view["operation_digest"],
        ),
    )
    for update in (
        {"human_uid": 1004},
        {"nonce": "0" * 64},
        {"operation_digest": "0" * 64},
        {"password": "invalid-field"},
    ):
        assert rpc("control", confirm | {"body": confirm["body"] | update}, actor="root") == denied
    approved = human({"mode": "confirm", "view": view, "password": password})
    assert approved["ok"]
    assert human({"mode": "confirm", "view": view, "password": password}) == {"ok": False}
    body = proposal | {"grant_id": approved["grant_id"]}
    assert (
        rpc(
            "request",
            dict(
                schema_version="1.0", operation="propose", body=body | {"args": {"path": "other"}}
            ),
        )
        == denied
    )
    accepted = rpc("request", dict(schema_version="1.0", operation="propose", body=body))
    assert accepted["ok"] and accepted["fresh"] and accepted["action"]["state"] == "intent", (
        accepted
    )
    assert accepted["action"]["verified"] == 0
    inode = target.stat().st_ino
    held = []
    for file in Path(f"/proc/{pid}/fd").iterdir():
        try:
            info = file.stat()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if info.st_ino == inode and info.st_dev == target.stat().st_dev:
            held.append(int(file.name))
    assert held, "Broker did not retain the actual target descriptor"
    target.rename(WORK / "retained")
    target.symlink_to("/etc/mano/sentinel")
    assert all(Path(f"/proc/{pid}/fd/{fd}").stat().st_ino == inode for fd in held)
    replay = rpc("request", dict(schema_version="1.0", operation="propose", body=body))
    assert not replay["fresh"] and replay["action"]["id"] == accepted["action"]["id"]
    # Pending approval and executing-state recovery are independent of real effects.
    pending2 = rpc(
        "request",
        dict(
            schema_version="1.0",
            operation="request_approval",
            body=proposal | {"idempotency_key": "pending-restart"},
        ),
    )["approval"]
    seed = """import sys,time;from pathlib import Path;from mano_broker.state import State
s=State(Path('/var/lib/mano-broker/runtime'))
s.start(sys.argv[1],now=time.monotonic(),boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip());s.close()
"""
    subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            "mano-broker",
            "--",
            "env",
            "PYTHONPATH=/usr/lib/mano-os",
            "python3",
            "-c",
            seed,
            accepted["action"]["id"],
        ],
        check=True,
    )
    subprocess.run(["systemctl", "kill", "--signal=SIGKILL", "mano-broker.service"], check=True)
    replacement = ready(pid)
    status = rpc(
        "request",
        dict(
            schema_version="1.0",
            operation="status",
            body=dict(task_id=proposal["task_id"], action_id=accepted["action"]["id"]),
        ),
    )
    assert status["action"]["state"] == "unknown" and status["action"]["verified"] == 0
    assert rpc("request", dict(schema_version="1.0", operation="propose", body=body)) == denied
    pending_query = query | {"body": {"approval_id": pending2["approval_id"]}}
    assert rpc("request", pending_query)["approval"]["state"] == "revoked"
    reprovision = rpc("provision", envelope, actor="root", directory=WORK)
    assert (
        reprovision["resource_id"] != provision["resource_id"]
        and reprovision["task_id"] != provision["task_id"]
    )
    assert rpc("request", dict(schema_version="1.0", operation="propose", body=body)) == denied
    native_pid = int(
        command("systemctl", "show", "mano-approve.service", "--property=MainPID", "--value")
    )
    native_fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{native_pid}/status").read_text().splitlines()
        if ":" in line
    )
    assert (
        set(map(int, native_fields["Uid"].split())) == {0}
        and int(native_fields["CapEff"].strip(), 16) == 0
    )
    assert native_fields["NoNewPrivs"].strip() == "1" and native_fields["Seccomp"].strip() == "2"
    slow = subprocess.Popen(
        [
            "/usr/sbin/runuser",
            "-u",
            "mano-worker",
            "--",
            "python3",
            "-c",
            "import socket,time;s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);"
            "s.connect('/run/mano-broker/request.sock');time.sleep(4)",
        ]
    )
    time.sleep(0.2)
    started = time.monotonic()
    assert rpc("request", pending_query)["ok"]
    elapsed = time.monotonic() - started
    slow.wait(timeout=6)
    assert elapsed < 5
    # Actual allocated caller → kernel broker socket → native PAM → journal
    # → private root launcher → sandboxed terminal. No direct grant injection.
    identity = allocate_identity()
    terminal_workspace, terminal_fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    os.close(terminal_fd)
    terminal_task = rpc("provision", dict(schema_version="1.0", operation="provision_task",
        body=dict(human_uid=1002, caller_uid=identity.uid, mode="supervised",
                  classification="internal")), actor="root", directory=terminal_workspace)
    assert terminal_task["ok"]
    terminal_proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
        resource_id=terminal_task["resource_id"], capability="terminal.run",
        args=dict(argv=["/usr/bin/python3", "-c",
            "from pathlib import Path;"
            "Path('/workspace/live-result').write_text('pam-terminal-ok')"],
            cwd=".", timeout_seconds=10), idempotency_key="pam-terminal-once",
        reason="actual PAM-bound terminal integration")
    terminal_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=terminal_proposal), actor=identity.name)["approval"]
    terminal_view = human(dict(mode="view", id=terminal_pending["approval_id"]))["view"]
    assert human(dict(mode="confirm", view=terminal_view, password="wrong-ci-password")) == {
        "ok": False
    }
    assert not (terminal_workspace / "live-result").exists()
    terminal_grant = human(dict(mode="confirm", view=terminal_view, password=password))
    assert terminal_grant["ok"]
    terminal_body = terminal_proposal | {"grant_id": terminal_grant["grant_id"]}
    changed = terminal_body | {"args": terminal_body["args"] | {"timeout_seconds": 11}}
    assert rpc("request", dict(schema_version="1.0", operation="propose",
                               body=changed), actor=identity.name) == denied
    assert not (terminal_workspace / "live-result").exists()
    terminal_action = rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name)
    assert terminal_action["ok"] and terminal_action["fresh"]
    assert terminal_action["action"]["state"] == "intent"
    terminal_query = dict(schema_version="1.0", operation="status", body=dict(
        task_id=terminal_task["task_id"], action_id=terminal_action["action"]["id"]))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        terminal_status = rpc("request", terminal_query, actor=identity.name)["action"]
        if terminal_status["state"] in {"done", "failed", "unknown"}:
            break
        time.sleep(0.1)
    assert terminal_status["state"] == "done", terminal_status
    assert terminal_status["verified"] == 0
    assert (terminal_workspace / "live-result").read_text() == "pam-terminal-ok"
    captured = rpc("control", dict(schema_version="1.0", operation="capture_artifact",
        body=dict(action_id=terminal_action["action"]["id"], path="live-result")), actor="root")
    assert captured["ok"] and captured["artifact"]["effect_verified"] is False
    artifact_query = dict(schema_version="1.0", operation="artifact_read", body=dict(
        task_id=terminal_task["task_id"], artifact_id=captured["artifact"]["artifact_id"],
        offset=0, length=4096))
    artifact_read = rpc("request", artifact_query, actor=identity.name)
    assert artifact_read["ok"] and artifact_read["eof"]
    assert base64.b64decode(artifact_read["data"]) == b"pam-terminal-ok"
    assert artifact_read["artifact"]["effect_verified"] is False
    assert rpc("request", artifact_query) == denied
    assert rpc("request", artifact_query | {"body": artifact_query["body"] | {"length": 4097}},
        actor=identity.name) == denied
    assert rpc("request", dict(schema_version="1.0", operation="capture_artifact",
        body=dict(action_id=terminal_action["action"]["id"], path="live-result")),
        actor=identity.name) == denied
    terminal_replay = rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name)
    assert not terminal_replay["fresh"]
    assert terminal_replay["action"]["id"] == terminal_action["action"]["id"]
    assert terminal_replay["action"]["state"] == "done"
    assert rpc("request", terminal_query) == denied
    terminal_report = dict(actual_kernel_task_peer=True, allocated_task_uid=identity.uid,
        native_pam_grant=True, wrong_password_no_effect=True, changed_arguments_denied=True,
        durable_terminal_done=True,
        workspace_effect_observed=True, effect_verified=False, replay_no_execution=True,
        wrong_caller_status_denied=True, physical_input_provenance=None,
        production_broker_sealed_capture=True, actual_task_artifact_read=True,
        artifact_capture_request_denied=True, artifact_wrong_caller_and_range_denied=True)
    subprocess.run(["systemctl", "start", "mano-stopd.socket", "mano-stopd.service"], check=True)
    stop_pid = int(command(
        "systemctl", "show", "mano-stopd.service", "--property=MainPID", "--value"
    ))
    stop_fields = dict(line.split(":", 1) for line in Path(f"/proc/{stop_pid}/status").read_text()
                       .splitlines() if ":" in line)
    assert int(stop_fields["CapEff"].strip(), 16) == 0
    assert stop_fields["NoNewPrivs"].strip() == "1" and stop_fields["Seccomp"].strip() == "2"
    stop_proposal = terminal_proposal | dict(idempotency_key="native-stop-task", args=dict(
        argv=["/usr/bin/python3", "-c", "import os,time;from pathlib import Path;"
              "p=os.fork()\nif p==0:\n os.setsid()\n"
              " Path('/workspace/stoppable').write_text('ready')\ntime.sleep(60)"],
        cwd=".", timeout_seconds=60))
    pending_stop = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=stop_proposal), actor=identity.name)["approval"]
    stop_view = human(dict(mode="view", id=pending_stop["approval_id"]))["view"]
    stop_grant = human(dict(mode="confirm", view=stop_view, password=password))
    assert stop_grant["ok"]
    stop_action = rpc("request", dict(schema_version="1.0", operation="propose",
        body=stop_proposal | {"grant_id": stop_grant["grant_id"]}), actor=identity.name)
    group = Path("/sys/fs/cgroup/system.slice/mano-launcher.service") / (
        "task-" + stop_action["action"]["id"])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if (terminal_workspace / "stoppable").exists():
            break
        time.sleep(0.1)
    assert (terminal_workspace / "stoppable").read_text() == "ready"
    assert len((group / "cgroup.procs").read_text().split()) >= 2
    stop_client = """import socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(3)
s.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
s.connect('/run/mano-stopd/human.sock');s.sendall(sys.argv[1].encode())
reply,ancillary,flags,_=s.recvmsg(32,socket.CMSG_SPACE(12))
assert not flags and len(ancillary)==1
assert ancillary[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS)
pid,uid,gid=struct.unpack('3i',ancillary[0][2])
assert pid==int(sys.argv[3]) and uid==0 and gid==0
assert reply==sys.argv[2].encode()
"""
    subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--", "python3", "-c",
        stop_client, "SS", "denied", str(stop_pid)], check=True, capture_output=True,
        text=True, timeout=5)
    assert (STOP_STATE / "state").read_text() == "v1:0:armed\n"
    denied_client = """import errno,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
try:s.connect('/run/mano-stopd/human.sock')
except PermissionError as e:assert e.errno==errno.EACCES
else:raise AssertionError('task reached native Stop')
"""
    subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--", "python3", "-c",
                    denied_client], check=True, capture_output=True, text=True, timeout=5)
    pending_revoke = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=terminal_proposal | {"idempotency_key": "pending-native-stop"}),
        actor=identity.name)["approval"]
    broker_pid = ready()
    launcher_pid = int(command(
        "systemctl", "show", "mano-launcher.service", "--property=MainPID", "--value"
    ))
    subprocess.run(["kill", "-STOP", str(broker_pid), str(launcher_pid)], check=True)
    try:
        subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--", "python3", "-c",
                        stop_client, "S", "stopped", str(stop_pid)], check=True,
                       capture_output=True, text=True, timeout=5)
        deadline = time.monotonic() + 3
        while (time.monotonic() < deadline
               and "populated 1" in (group / "cgroup.events").read_text()):
            time.sleep(0.05)
        assert "populated 0" in (group / "cgroup.events").read_text()
        assert (STOP_STATE / "state").read_text() == "v1:1:latched\n"
        for frozen in (broker_pid, launcher_pid):
            assert "T" in next(line for line in Path(f"/proc/{frozen}/status").read_text()
                               .splitlines() if line.startswith("State:"))
    finally:
        subprocess.run(["kill", "-CONT", str(broker_pid), str(launcher_pid)], check=False)
    terminal_report["native_stop_broker_and_launcher_frozen"] = True
    terminal_report["native_stop_capabilities_zero"] = True
    terminal_report["native_stop_task_cgroup_drained"] = True
    terminal_report["native_stop_latch_written"] = True
    query_stop = dict(schema_version="1.0", operation="status", body=dict(
        task_id=terminal_task["task_id"], action_id=stop_action["action"]["id"]))
    stopped_status = rpc("request", query_stop, actor=identity.name)["action"]
    assert stopped_status["state"] == "unknown" and stopped_status["verified"] == 0
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name) == denied
    revoked = rpc("request", dict(schema_version="1.0", operation="approval_status",
        body=dict(approval_id=pending_revoke["approval_id"])), actor=identity.name)
    assert revoked["approval"]["state"] == "revoked"
    private_denial = """import array,json,os,sys
from mano_broker.launch_client import Client
packet=json.loads(sys.stdin.read());fds=[]
try:
 fds=[os.open(sys.argv[1],os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC) for _ in range(2)]
 c=Client();result=c.exchange('prepare',packet,fds);c.close()
 assert result['ok'] is False
finally:
 for fd in fds:os.close(fd)
"""
    negative = dict(schema_version="1.0", operation="launch_task", body=dict(
        action_id="f" * 32, caller_uid=identity.uid, request=terminal_body,
        limits=dict(memory_bytes=64*1024**2, pids=16, cpu_percent=10)))
    subprocess.run(["/usr/sbin/runuser", "-u", "mano-broker", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", private_denial, str(terminal_workspace)],
        input=json.dumps(negative), text=True, capture_output=True, check=True, timeout=10)
    subprocess.run(["systemctl", "kill", "--signal=SIGKILL", "mano-broker.service"], check=True)
    ready(broker_pid)
    recovered_artifact = rpc("request", artifact_query, actor=identity.name)
    assert base64.b64decode(recovered_artifact["data"]) == b"pam-terminal-ok"
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name) == denied
    assert (STOP_STATE / "state").read_text() == "v1:1:latched\n"
    terminal_report["native_stop_grant_latch_integrated"] = True
    terminal_report["native_stop_pending_revoked"] = True
    terminal_report["native_stop_root_preparation_denied"] = True
    terminal_report["native_stop_restart_no_rearm"] = True
    # Fault-inject an interrupted native state write while its daemon is stopped.
    subprocess.run(["systemctl", "stop", "mano-stopd.service"], check=True)
    pending_file = STOP_STATE / "state.pending"
    pending_file.write_text("v1:2:arm")
    pending_file.chmod(0o644)
    subprocess.run(["systemctl", "start", "mano-stopd.service"], check=True)
    assert not pending_file.exists()
    assert (STOP_STATE / "state").read_text() == "v1:2:latched\n"
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name) == denied
    terminal_report["native_stop_interrupted_write_recovers_latched"] = True
    subprocess.run(["systemctl", "stop", "mano-stopd.service"], check=True)
    pending_file.write_text("v1:3:armed\n")
    pending_file.chmod(0o644)
    subprocess.run(["systemctl", "start", "mano-stopd.service"], check=True)
    assert not pending_file.exists()
    assert (STOP_STATE / "state").read_text() == "v1:4:latched\n"
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name) == denied
    terminal_report["native_stop_interrupted_arm_recovers_latched"] = True
    terminal_report["native_stop_generation"] = 4
    rearm_view = human(dict(mode="rearm_view"))["view"]
    assert rearm_view["generation"] == 4 and rearm_view["human_uid"] == 1002
    assert human(dict(mode="rearm_view"), actor=identity.name) == {"ok": False}
    assert human(dict(mode="rearm_confirm", view=rearm_view, password="wrong-ci-password")) == {
        "ok": False
    }
    assert (STOP_STATE / "state").read_text() == "v1:4:latched\n"
    assert human(dict(mode="rearm_confirm", view=rearm_view | {"nonce": "0"*64},
                      password=password)) == {"ok": False}
    rearm_view = human(dict(mode="rearm_view"))["view"]
    broker_pid = ready()
    stop_pid = int(command("systemctl", "show", "mano-stopd.service",
                           "--property=MainPID", "--value"))
    subprocess.run(["kill", "-STOP", str(broker_pid)], check=True)
    try:
        subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--", "python3", "-c",
            stop_client, "S", "stopped", str(stop_pid)], check=True, capture_output=True,
            text=True, timeout=5)
        assert human(dict(mode="rearm_confirm", view=rearm_view, password=password)) == {
            "ok": False
        }
        fresh_rearm = human(dict(mode="rearm_view"))["view"]
        assert fresh_rearm["generation"] == 5
        armed = human(dict(mode="rearm_confirm", view=fresh_rearm, password=password))
        assert armed["ok"] and armed["rearmed"] and armed["generation"] == 6
        assert "T" in next(line for line in Path(f"/proc/{broker_pid}/status").read_text()
                           .splitlines() if line.startswith("State:"))
    finally:
        subprocess.run(["kill", "-CONT", str(broker_pid)], check=False)
    assert human(dict(mode="rearm_confirm", view=fresh_rearm, password=password)) == {"ok": False}
    assert (STOP_STATE / "state").read_text() == "v1:6:armed\n"
    # Fresh provisioning is required after the prior broker restarts; old grants
    # remain revoked even when native rearm was completed while Python was frozen.
    task_after = rpc("provision", dict(schema_version="1.0", operation="provision_task",
        body=dict(human_uid=1002, caller_uid=identity.uid, mode="supervised",
                  classification="internal")), actor="root", directory=terminal_workspace)
    proposal_after = terminal_proposal | dict(task_id=task_after["task_id"],
        resource_id=task_after["resource_id"], idempotency_key="after-native-rearm", args=dict(
            argv=["/usr/bin/python3", "-c", "from pathlib import Path;"
                  "Path('/workspace/rearmed-result').write_text('rearmed-ok')"],
            cwd=".", timeout_seconds=10))
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=proposal_after | {"grant_id": terminal_grant["grant_id"]}),
        actor=identity.name) == denied
    after_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=proposal_after), actor=identity.name)["approval"]
    after_view = human(dict(mode="view", id=after_pending["approval_id"]))["view"]
    after_grant = human(dict(mode="confirm", view=after_view, password=password))
    assert after_grant["ok"]
    after_action = rpc("request", dict(schema_version="1.0", operation="propose",
        body=proposal_after | {"grant_id": after_grant["grant_id"]}), actor=identity.name)
    after_query = dict(schema_version="1.0", operation="status", body=dict(
        task_id=task_after["task_id"], action_id=after_action["action"]["id"]))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        after_status = rpc("request", after_query, actor=identity.name)["action"]
        if after_status["state"] in {"done", "failed", "unknown"}:
            break
        time.sleep(0.1)
    assert after_status["state"] == "done" and after_status["verified"] == 0
    assert (terminal_workspace / "rearmed-result").read_text() == "rearmed-ok"
    terminal_report.update(native_pam_rearm=True, rearm_wrong_password_denied=True,
        rearm_bad_nonce_denied=True, newer_stop_invalidates_rearm=True, rearm_replay_denied=True,
        frozen_broker_rearm=True, old_grant_not_resurrected=True,
        fresh_pam_terminal_after_rearm=True, native_stop_generation=6)


    grant_observer = """import sqlite3,sys
s=sqlite3.connect('file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro',uri=True)
assert s.execute('SELECT revoked FROM grants WHERE id=?',(sys.argv[1],)).fetchone()[0]==1
assert s.execute("SELECT value FROM meta WHERE key='native_generation'").fetchone()[0]==6
s.close()
"""
    subprocess.run(["/usr/sbin/runuser", "-u", "mano-broker", "--", "python3", "-c",
        grant_observer, terminal_grant["grant_id"]], check=True, capture_output=True,
        text=True, timeout=5)
    stop_pid = int(command("systemctl", "show", "mano-stopd.service",
                           "--property=MainPID", "--value"))
    subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--", "python3", "-c",
        stop_client, "S", "stopped", str(stop_pid)], check=True, capture_output=True,
        text=True, timeout=5)
    assert (STOP_STATE / "state").read_text() == "v1:7:latched\n"
    expired_view = human(dict(mode="rearm_view"))["view"]
    time.sleep(61)  # Real monotonic expiry; no configurable shortcut or clock spoof.
    assert human(dict(mode="rearm_confirm", view=expired_view, password=password)) == {"ok": False}
    assert (STOP_STATE / "state").read_text() == "v1:7:latched\n"
    subprocess.run(["systemctl", "start", "mano-launcher.service"], check=True)
    # Trusted operator fault injection only: emulate an undrained task leaf.
    # Production Controller still forbids preparing while the native latch is set.
    injected = Path("/sys/fs/cgroup/system.slice/mano-launcher.service/task-" + "c"*32)
    assert not injected.exists()
    injected.mkdir(mode=0o700)
    (injected / "memory.max").write_text(str(64*1024**2))
    (injected / "pids.max").write_text("4")
    (injected / "cpu.max").write_text("10000 100000")
    gate_r, gate_w = os.pipe()
    sleeper = os.fork()
    if sleeper == 0:
        try:
            os.close(gate_w)
            if os.read(gate_r, 1) != b'g':
                os._exit(125)
            os.close(gate_r)
            os.setgroups([])
            os.setgid(identity.gid)
            os.setuid(identity.uid)
            time.sleep(30)
            os._exit(0)
        except BaseException:
            os._exit(125)  # Never enter the operator parent's cleanup from this child.

    os.close(gate_r)
    try:
        (injected / "cgroup.procs").write_text(str(sleeper))
        os.write(gate_w, b'g')
        os.close(gate_w)
        gate_w = -1
        assert "populated 1" in (injected / "cgroup.events").read_text()
        undrained_view = human(dict(mode="rearm_view"))["view"]
        assert human(dict(mode="rearm_confirm", view=undrained_view, password=password)) == {
            "ok": False
        }
        assert (STOP_STATE / "state").read_text() == "v1:7:latched\n"
    finally:
        if gate_w >= 0:
            os.close(gate_w)
        (injected / "cgroup.kill").write_text("1")
        os.waitpid(sleeper, 0)
        assert "populated 0" in (injected / "cgroup.events").read_text()
        injected.rmdir()
    drained_view = human(dict(mode="rearm_view"))["view"]
    assert human(dict(mode="rearm_confirm", view=drained_view, password=password))["rearmed"]
    assert (STOP_STATE / "state").read_text() == "v1:8:armed\n"
    original_launcher = int(command("systemctl", "show", "mano-launcher.service",
                                    "--property=MainPID", "--value"))
    subprocess.run(["systemctl", "restart", "mano-launcher.service"], check=True)
    replacement_launcher = int(command("systemctl", "show", "mano-launcher.service",
                                       "--property=MainPID", "--value"))
    assert replacement_launcher and replacement_launcher != original_launcher
    # Broker transport pins launcher process identity; explicit broker recovery
    # must renew that identity and require new provisioning and fresh approval.
    previous_broker = ready()
    subprocess.run(["systemctl", "restart", "mano-broker.service"], check=True)
    ready(previous_broker)
    replaced_task = rpc("provision", dict(schema_version="1.0", operation="provision_task",
        body=dict(human_uid=1002, caller_uid=identity.uid, mode="supervised",
                  classification="internal")), actor="root", directory=terminal_workspace)
    replaced_proposal = terminal_proposal | dict(task_id=replaced_task["task_id"],
        resource_id=replaced_task["resource_id"], idempotency_key="replacement-stop", args=dict(
            argv=["/usr/bin/python3", "-c", "import time;from pathlib import Path;"
                  "Path('/workspace/replacement-ready').write_text('ready');time.sleep(60)"],
            cwd=".", timeout_seconds=60))
    replaced_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=replaced_proposal), actor=identity.name)["approval"]
    replaced_view = human(dict(mode="view", id=replaced_pending["approval_id"]))["view"]
    replaced_grant = human(dict(mode="confirm", view=replaced_view, password=password))
    assert replaced_grant["ok"]
    replaced_action = rpc("request", dict(schema_version="1.0", operation="propose",
        body=replaced_proposal | {"grant_id": replaced_grant["grant_id"]}), actor=identity.name)
    replaced_group = Path("/sys/fs/cgroup/system.slice/mano-launcher.service/task-" +
                          replaced_action["action"]["id"])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not (terminal_workspace / "replacement-ready").exists():
        time.sleep(0.1)
    assert (terminal_workspace / "replacement-ready").read_text() == "ready"
    assert int(command("systemctl", "show", "mano-stopd.service",
                       "--property=MainPID", "--value")) == stop_pid
    subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--", "python3", "-c",
        stop_client, "S", "stopped", str(stop_pid)], check=True, capture_output=True,
        text=True, timeout=5)
    deadline = time.monotonic() + 3
    replacement_drained = False
    while time.monotonic() < deadline:
        try:
            replacement_drained = "populated 0" in (replaced_group / "cgroup.events").read_text()
        except FileNotFoundError:
            replacement_drained = True  # Root controller removed its empty completed group.
        if replacement_drained:
            break
        time.sleep(0.05)
    assert replacement_drained
    terminal_report.update(rearm_expired_denied=True, rearm_populated_group_denied=True,
        old_grant_journal_revocation_observed=True,
        rearm_after_drain=True, native_stop_replacement_launcher_drained=True,
        native_stop_generation=9)
    native_report = dict(
        real_pam_authenticated=True,
        wrong_password_denied=True,
        changed_nonce_denied=True,
        replay_denied=True,
        grant_consumed_by_exact_request=True,
        unauthorized_human_socket_actors=["mano-agent", "mano-core", "mano-worker"],
        native_uid=0,
        effective_capabilities=0,
        no_new_privs=True,
        seccomp_filter=True,
        binary_sha256=hashlib.sha256(NATIVE.read_bytes()).hexdigest(),
        physical_input_provenance=None,
        scope="synthetic CI OS authentication; physical TTY UI not exercised",
    )
    del password
    print(
        json.dumps(
            dict(
                scope="live broker/PAM/allocated-task terminal execution in disposable VM",
                broker_uid=broker_uid,
                no_new_privs=True,
                seccomp_filter=True,
                effective_capabilities=0,
                service_limits=limits,
                kernel_denials=denials,
                native_pam=native_report,
                terminal_execution=terminal_report,
                real_root_fd_provisioned=True,
                prepared_target_fd_verified=True,
                mutation_syscalls_kernel_denied=True,
                root_control_reply_credentials_verified=True,
                confirmation_binding_denials=4,
                target_inode_retained_after_replacement=True,
                replay_no_new_preparation=True,
                actual_sigkill_restart=True,
                restart_pid_changed=pid != replacement,
                unknown_preserved_no_replay=True,
                pending_authority_revoked_on_restart=True,
                lost_resource_denied=True,
                fresh_provisioning_required=True,
                slow_client_bounded_seconds=elapsed,
                no_operation_executed=False,
                execution_state_seeded_for_recovery=True,
                model_connected=False,
                production_execution_authorized=False,
            ),
            indent=2,
        )
    )
except BaseException:
    subprocess.run(
        [
            "journalctl",
            "-u",
            "mano-broker.service",
            "-u",
            "mano-approve.service",
            "--no-pager",
            "-n",
            "80",
        ],
        stdout=sys.stderr,
        stderr=sys.stderr,
        check=False,
        timeout=10,
    )
    raise
finally:
    subprocess.run(["systemctl", "stop", *UNITS], check=False, capture_output=True)
    subprocess.run(["usermod", "-L", "mano-human"], check=False, capture_output=True)
    for file in (LIBRARY, NATIVE, STOP_NATIVE, POLICY, PAM, GUARD, *installed):
        file.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    subprocess.run(
        ["systemctl", "reset-failed", "mano-broker.service", "mano-approve.service"],
        check=False,
        capture_output=True,
    )
    for directory in (STATE, CODE, WORK, BASE, STOP_STATE):
        if directory.exists():
            shutil.rmtree(directory)
    STATE.parent.chmod(old_mode)
    if identity is not None:
        subprocess.run(["userdel", identity.name], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)
    stop_dir = Path("/run/mano-stopd")
    if stop_dir.exists():
        stop_dir.rmdir()
    launcher_dir = Path("/run/mano-launcher")
    if launcher_dir.exists():
        launcher_dir.rmdir()
    if joined:
        subprocess.run(
            ["gpasswd", "-d", "mano-worker", "mano-request"], check=False, capture_output=True
        )
    if created_user:
        subprocess.run(["userdel", "mano-broker"], check=False, capture_output=True)
    if created_group:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
