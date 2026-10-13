#!/usr/bin/env python3
"""Install/start/restart the real non-root broker in a fixed disposable guest."""

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
PARENT = STATE.parent
CODE = Path("/usr/lib/mano-os")
SOCKET = Path("/run/mano-broker/request.sock")
CONTROL = Path("/run/mano-broker/control.sock")
UNITS = (
    "mano-broker.service",
    "mano-broker.socket",
    "mano-broker-control.socket",
    "mano-approve.service",
    "mano-approve.socket",
)
NATIVE = Path("/usr/libexec/mano-approve")
HUMAN_POLICY = Path("/etc/mano/human.uid")
PAM_CONFIG = Path("/etc/pam.d/mano-approve")
assert not NATIVE.exists() and not HUMAN_POLICY.exists() and not PAM_CONFIG.exists()
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not STATE.exists() and not CODE.exists() and not SOCKET.exists() and not CONTROL.exists()
assert all(not (Path("/etc/systemd/system") / unit).exists() for unit in UNITS)
old_mode = PARENT.stat().st_mode & 0o777
installed = []
created_user = False
created_group = False
worker_joined = False


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def wait_service(previous=None):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        pid = int(
            command("systemctl", "show", "mano-broker.service", "--property=MainPID", "--value")
        )
        active = command(
            "systemctl", "show", "mano-broker.service", "--property=ActiveState", "--value"
        )
        if pid and active == "active" and pid != previous:
            return pid
        time.sleep(0.2)
    raise AssertionError("Service not ready")


client = """import errno,json,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5)
try:s.connect(sys.argv[1])
except PermissionError as e:
 assert e.errno==errno.EACCES;print(json.dumps({'kernel_errno':'EACCES'}));sys.exit(0)
s.sendall(sys.stdin.buffer.read());print(s.recv(65536).decode())
"""


def request(actor, body):
    result = subprocess.run(
        ["/usr/sbin/runuser", "-u", actor, "--", "python3", "-c", client, str(SOCKET)],
        input=json.dumps(body),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return json.loads(result.stdout)


control_client = """import errno,json,socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5)
s.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
try:s.connect(sys.argv[1])
except PermissionError as e:
 assert e.errno==errno.EACCES;print(json.dumps({'kernel_errno':'EACCES'}));sys.exit(0)
_,creator_uid,_=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert creator_uid==0,('unexpected socket creator',creator_uid)
s.sendall(sys.stdin.buffer.read())
packet,ancillary,flags,_=s.recvmsg(131072,socket.CMSG_SPACE(12))
assert not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
assert len(ancillary)==1 and ancillary[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS)
pid,uid,_=struct.unpack('3i',ancillary[0][2])
assert uid==int(sys.argv[2]) and pid==int(sys.argv[3]),('unexpected reply sender',pid,uid)
print(packet.decode())
"""


def control_rpc(body, actor="root"):
    result = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            actor,
            "--",
            "python3",
            "-c",
            control_client,
            str(CONTROL),
            str(broker_uid),
            str(replacement),
        ],
        input=json.dumps(body),
        capture_output=True,
        text=True,
        timeout=10,
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
    subprocess.run(["usermod", "-a", "-G", "mano-request", "mano-worker"], check=True)
    worker_joined = True
    broker_uid = pwd.getpwnam("mano-broker").pw_uid
    broker_gid = pwd.getpwnam("mano-broker").pw_gid
    assert broker_uid not in {0, 1001, 1002, 1003, 1004}
    CODE.mkdir(mode=0o755)
    shutil.copytree(
        ROOT / "src/mano_broker", CODE / "mano_broker", ignore=shutil.ignore_patterns("__pycache__")
    )
    for file in (CODE / "mano_broker").rglob("*.py"):
        file.chmod(0o444)
    (CODE / "mano_broker").chmod(0o555)
    PARENT.chmod(0o711)
    STATE.mkdir(mode=0o700)
    os.chown(STATE, broker_uid, broker_gid)
    seed = """import json,time;from pathlib import Path
from mano_broker.state import State
from mano_broker.protocol import ActionRequest
s=State(Path('/var/lib/mano-broker/runtime'));boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
t=s.create_task(human_uid=1002,caller_uid=1004,mode='supervised',resource_id='a'*32,classification='internal',boot_id=boot)
g=s.issue_grant(t,approved_human_uid=1002,approved_args={'path':'file'},capability='files.read',resource_id='a'*32,expires=time.monotonic()+300,max_count=2,memory_bytes=1048576,pids=4,cpu_percent=10,max_timeout_seconds=10)
b=dict(schema_version='1.0',task_id=t,grant_id=g,capability='files.read',
 resource_id='a'*32,args={'path':'file'},idempotency_key='pre-restart',reason='fixed CI seed')
a,_=s.authorize(ActionRequest.parse(json.dumps(b).encode()),caller_uid=1004,now=time.monotonic(),boot_id=boot)
s.start(a['id'],now=time.monotonic(),boot_id=boot);s.close();print(json.dumps(b))
"""
    seed_body = json.loads(
        command(
            "/usr/sbin/runuser",
            "-u",
            "mano-broker",
            "--",
            "env",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "python3",
            "-c",
            seed,
        )
    )
    for unit in UNITS:
        dest = Path("/etc/systemd/system") / unit
        shutil.copyfile(ROOT / "packaging/systemd" / unit, dest)
        installed.append(dest)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "start", "mano-broker.socket"], check=True)
    packet = dict(schema_version="1.0", operation="propose", body=seed_body)
    recovered = request("mano-worker", packet)
    assert recovered["ok"] and not recovered["fresh"] and recovered["action"]["state"] == "unknown"
    pid = wait_service()
    fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        if ":" in line
    )
    assert set(map(int, fields["Uid"].split())) == {broker_uid}
    assert fields["NoNewPrivs"].strip() == "1" and fields["Seccomp"].strip() == "2"
    assert int(fields["CapEff"].strip(), 16) == 0
    stat = SOCKET.stat()
    assert stat.st_uid == 0 and stat.st_mode & 0o777 == 0o660
    assert CONTROL.stat().st_uid == 0 and CONTROL.stat().st_mode & 0o777 == 0o600
    assert STATE.stat().st_uid == broker_uid and STATE.stat().st_mode & 0o777 == 0o700
    assert (STATE / "state.sqlite3").stat().st_mode & 0o777 == 0o600
    properties = {
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
    assert properties["TasksMax"] == "16" and properties["MemoryMax"] == "134217728"
    assert properties["ProtectSystem"] == "strict" and properties["ProtectHome"] == "yes"
    denials = []
    for actor in ("mano-agent", "mano-core", "mano-human"):
        assert request(actor, packet) == {"kernel_errno": "EACCES"}
        denials.append({"actor": actor, "target": "request-socket", "kernel_errno": "EACCES"})
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
                "else:raise AssertionError('private journal read')",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr
        denials.append({"actor": actor, "target": "private-journal", "kernel_errno": "EACCES"})
    altered = request(
        "mano-worker",
        packet
        | {"body": seed_body | {"args": {"path": "other"}, "idempotency_key": "changed-target"}},
    )
    assert altered == {"schema_version": "1.0", "ok": False, "error": "denied"}
    # One incomplete client cannot stall the watchdog or the next valid request indefinitely.
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
    body = seed_body | {"idempotency_key": "new-request"}
    started = time.monotonic()
    fresh = request("mano-worker", packet | {"body": body})
    elapsed = time.monotonic() - started
    slow.wait(timeout=6)
    assert fresh["ok"] and fresh["fresh"] and elapsed < 5
    approval_proposal = {key: value for key, value in seed_body.items() if key != "grant_id"}
    pending = request(
        "mano-worker",
        {
            "schema_version": "1.0",
            "operation": "request_approval",
            "body": approval_proposal | {"idempotency_key": "pending-human"},
        },
    )
    assert pending["ok"] and pending["approval"]["state"] == "pending"
    assert pending["approval"]["grant_id"] is None
    assert set(pending["approval"]) == {"approval_id", "state", "grant_id"}
    approval_query = {
        "schema_version": "1.0",
        "operation": "approval_status",
        "body": {"approval_id": pending["approval"]["approval_id"]},
    }
    assert request("mano-worker", approval_query) == pending
    assert request("mano-worker", approval_query | {"operation": "approve"}) == {
        "schema_version": "1.0",
        "ok": False,
        "error": "denied",
    }
    # Real process kill triggers systemd restart; journal identity and unknown state persist.
    subprocess.run(["systemctl", "kill", "--signal=SIGKILL", "mano-broker.service"], check=True)
    replacement = wait_service(pid)
    again = request("mano-worker", packet)
    assert again["ok"] and not again["fresh"] and again["action"] == recovered["action"]
    assert request("mano-worker", approval_query) == pending
    view_request = {
        "schema_version": "1.0",
        "operation": "approval_view",
        "body": {"approval_id": pending["approval"]["approval_id"], "human_uid": 1002},
    }
    for actor in ("mano-agent", "mano-core", "mano-worker", "mano-human"):
        assert control_rpc(view_request, actor) == {"kernel_errno": "EACCES"}
        denials.append(
            {"actor": actor, "target": "approval-control-socket", "kernel_errno": "EACCES"}
        )
    view = control_rpc(view_request)["view"]
    confirmation = {
        "schema_version": "1.0",
        "operation": "confirm_approval",
        "body": {
            "approval_id": view["approval_id"],
            "human_uid": 1002,
            "nonce": view["nonce"],
            "operation_digest": view["operation_digest"],
        },
    }
    denied = {"schema_version": "1.0", "ok": False, "error": "denied"}
    for change in (
        {"human_uid": 1004},
        {"nonce": "0" * 64},
        {"operation_digest": "0" * 64},
        {"password": "not-a-control-field"},
    ):
        assert control_rpc(confirmation | {"body": confirmation["body"] | change}) == denied
    approved = control_rpc(confirmation)
    assert approved["ok"]
    assert control_rpc(confirmation) == denied
    status = request("mano-worker", approval_query)
    assert status["approval"]["state"] == "approved"
    assert status["approval"]["grant_id"] == approved["grant_id"]
    new_body = approval_proposal | {
        "idempotency_key": "pending-human",
        "grant_id": approved["grant_id"],
    }
    assert (
        request("mano-worker", packet | {"body": new_body | {"args": {"path": "other"}}}) == denied
    )
    accepted = request("mano-worker", packet | {"body": new_body})
    assert accepted["ok"] and accepted["fresh"] and accepted["action"]["verified"] == 0
    # Real native PAM adapter: synthetic CI account only, never a host password.
    shutil.copytree(
        ROOT / "src/mano_prompt", CODE / "mano_prompt", ignore=shutil.ignore_patterns("__pycache__")
    )
    NATIVE.parent.mkdir(mode=0o755, exist_ok=True)
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
    HUMAN_POLICY.write_text("1002\n")
    HUMAN_POLICY.chmod(0o600)
    shutil.copyfile(ROOT / "packaging/pam/mano-approve", PAM_CONFIG)
    password = secrets.token_hex(24)
    subprocess.run(
        ["chpasswd"],
        input="mano-human:" + password + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    subprocess.run(["systemctl", "start", "mano-approve.socket"], check=True)
    native_proposal = approval_proposal | {"idempotency_key": "native-pam"}
    native_pending = request(
        "mano-worker",
        {"schema_version": "1.0", "operation": "request_approval", "body": native_proposal},
    )
    native_id = native_pending["approval"]["approval_id"]
    native_client = """import json,sys
from mano_prompt.approve import rpc,view_packet,confirmation_packet
body=json.loads(sys.stdin.read())
try:
 if body['mode']=='view':result=rpc(view_packet(body['id']))
 else:result=rpc(confirmation_packet(body['view'],body['password']))
except (PermissionError,ValueError):result={'ok':False}
print(json.dumps(result))
"""

    def native_rpc(actor, body):
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

    native_denials = []
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        assert native_rpc(actor, {"mode": "view", "id": native_id}) == {"ok": False}
        native_denials.append(actor)
    human_view = native_rpc("mano-human", {"mode": "view", "id": native_id})["view"]
    assert human_view["human_uid"] == 1002 and human_view["approval_id"] == native_id
    wrong = native_rpc(
        "mano-human", {"mode": "confirm", "view": human_view, "password": "wrong-ci-password"}
    )
    assert wrong == {"ok": False}
    native_query = {
        "schema_version": "1.0",
        "operation": "approval_status",
        "body": {"approval_id": native_id},
    }
    assert request("mano-worker", native_query)["approval"]["grant_id"] is None
    changed = human_view | {"nonce": "0" * 64}
    assert native_rpc("mano-human", {"mode": "confirm", "view": changed, "password": password}) == {
        "ok": False
    }
    authorized = native_rpc(
        "mano-human", {"mode": "confirm", "view": human_view, "password": password}
    )
    assert authorized["ok"]
    assert native_rpc(
        "mano-human", {"mode": "confirm", "view": human_view, "password": password}
    ) == {"ok": False}
    native_status = request("mano-worker", native_query)
    assert native_status["approval"]["grant_id"] == authorized["grant_id"]
    native_body = native_proposal | {"grant_id": authorized["grant_id"]}
    assert request("mano-worker", packet | {"body": native_body})["fresh"]
    native_pid = int(
        command("systemctl", "show", "mano-approve.service", "--property=MainPID", "--value")
    )
    native_fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{native_pid}/status").read_text().splitlines()
        if ":" in line
    )
    assert set(map(int, native_fields["Uid"].split())) == {0}
    assert int(native_fields["CapEff"].strip(), 16) == 0
    assert native_fields["NoNewPrivs"].strip() == "1" and native_fields["Seccomp"].strip() == "2"
    native_report = dict(
        real_pam_authenticated=True,
        wrong_password_denied=True,
        changed_nonce_denied=True,
        replay_denied=True,
        grant_consumed_by_exact_request=True,
        unauthorized_human_socket_actors=native_denials,
        native_uid=0,
        effective_capabilities=0,
        no_new_privs=True,
        seccomp_filter=True,
        binary_sha256=hashlib.sha256(NATIVE.read_bytes()).hexdigest(),
        physical_input_provenance=None,
        scope="synthetic CI OS authentication; physical TTY UI not exercised",
    )
    del password

    assert command("systemctl", "is-active", "mano-broker.socket") == "active"
    print(
        json.dumps(
            dict(
                scope="non-root broker with native PAM adapter; executor not integrated",
                broker_uid=broker_uid,
                no_new_privs=True,
                seccomp_filter=True,
                effective_capabilities=0,
                root_socket_mode="0660",
                private_state_mode="0700",
                private_database_mode="0600",
                service_limits=properties,
                kernel_denials=denials,
                slow_client_bounded_seconds=elapsed,
                actual_sigkill_restart=True,
                restart_pid_changed=pid != replacement,
                unknown_preserved_no_replay=True,
                approved_target_change_denied=True,
                durable_pending_approval=True,
                self_approval_wire_denied=True,
                root_control_single_confirmation=True,
                confirmation_binding_denials=4,
                control_pam_authenticated=False,
                root_control_reply_credentials_verified=True,
                native_pam=native_report,
                model_connected=False,
                production_execution_authorized=False,
            ),
            indent=2,
        )
    )
except BaseException:
    subprocess.run(
        ["journalctl", "-u", "mano-broker.service", "--no-pager", "-n", "60"],
        stdout=sys.stderr,
        stderr=sys.stderr,
        check=False,
        timeout=10,
    )
    raise
finally:
    subprocess.run(["systemctl", "stop", *UNITS], check=False, capture_output=True)
    subprocess.run(["usermod", "-L", "mano-human"], check=False, capture_output=True)
    for file in (NATIVE, HUMAN_POLICY, PAM_CONFIG):
        file.unlink(missing_ok=True)
    for file in installed:
        file.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    subprocess.run(
        ["systemctl", "reset-failed", "mano-broker.service"], check=False, capture_output=True
    )
    if STATE.exists():
        shutil.rmtree(STATE)
    if CODE.exists():
        shutil.rmtree(CODE)
    PARENT.chmod(old_mode)
    if worker_joined:
        subprocess.run(
            ["gpasswd", "-d", "mano-worker", "mano-request"], check=False, capture_output=True
        )
    if created_user:
        subprocess.run(["userdel", "mano-broker"], check=False, capture_output=True)
    if created_group:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
