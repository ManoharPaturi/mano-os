#!/usr/bin/env python3
"""Actual provision/PAM/descriptor preparation service flow in disposable Debian."""

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

ROOT = Path("/opt/mano-lab")
STATE = Path("/var/lib/mano-broker/runtime")
CODE = Path("/usr/lib/mano-os")
WORK = Path("/run/mano-live-workspace-ci")
LIBRARY = Path("/usr/lib/mano-broker/libmano-resources.so")
NATIVE = Path("/usr/libexec/mano-approve")
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
)
assert (
    os.geteuid() == 0 and Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
)
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert all(
    not p.exists() for p in (STATE, CODE, WORK, LIBRARY, NATIVE, POLICY, PAM, *SOCKETS.values())
)
assert all(not (Path("/etc/systemd/system") / u).exists() for u in UNITS)
old_mode = STATE.parent.stat().st_mode & 0o777
installed = []
created_user = False
created_group = False
joined = False


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
from mano_prompt.approve import rpc,view_packet,confirmation_packet
body=json.loads(sys.stdin.read())
try:
 if body['mode']=='view':result=rpc(view_packet(body['id']))
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
    for package in ("mano_broker", "mano_prompt"):
        shutil.copytree(
            ROOT / "src" / package, CODE / package, ignore=shutil.ignore_patterns("__pycache__")
        )
        for file in (CODE / package).rglob("*.py"):
            file.chmod(0o444)
        (CODE / package).chmod(0o555)
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
    subprocess.run(["systemctl", "start", "mano-broker.socket", "mano-approve.socket"], check=True)
    envelope = {
        "schema_version": "1.0",
        "operation": "provision_task",
        "body": dict(human_uid=1002, caller_uid=1004, mode="supervised", classification="internal"),
    }
    provision = rpc("provision", envelope, actor="root", directory=WORK)
    assert provision["ok"]
    pid = ready()
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
    assert accepted["ok"] and accepted["fresh"] and accepted["action"]["state"] == "intent"
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
                scope="live descriptor-provisioned request runtime; executor not integrated",
                broker_uid=broker_uid,
                no_new_privs=True,
                seccomp_filter=True,
                effective_capabilities=0,
                service_limits=limits,
                kernel_denials=denials,
                native_pam=native_report,
                real_root_fd_provisioned=True,
                prepared_target_fd_verified=True,
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
                no_operation_executed=True,
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
    for file in (LIBRARY, NATIVE, POLICY, PAM, *installed):
        file.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    subprocess.run(
        ["systemctl", "reset-failed", "mano-broker.service", "mano-approve.service"],
        check=False,
        capture_output=True,
    )
    for directory in (STATE, CODE, WORK):
        if directory.exists():
            shutil.rmtree(directory)
    STATE.parent.chmod(old_mode)
    if joined:
        subprocess.run(
            ["gpasswd", "-d", "mano-worker", "mano-request"], check=False, capture_output=True
        )
    if created_user:
        subprocess.run(["userdel", "mano-broker"], check=False, capture_output=True)
    if created_group:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
