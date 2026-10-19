#!/usr/bin/env python3
"""Actual provision/PAM/descriptor preparation service flow in disposable Debian."""

import base64
import contextlib
import hashlib
import json
import os
import pwd
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from ci_tty import native_terminal

from mano_broker.identities import LOCK, TaskIdentity
from mano_broker.sandbox import GUARD
from mano_broker.workspaces import BASE

ROOT = Path("/opt/mano-lab")
STATE = Path("/var/lib/mano-broker/runtime")
CODE = Path("/usr/lib/mano-os")
WORK = Path("/run/mano-live-workspace-ci")
LIBRARY = Path("/usr/lib/mano-broker/libmano-resources.so")
NATIVE = Path("/usr/libexec/mano-approve")
STOP_NATIVE = Path("/usr/libexec/mano-stopd")
STOP_CLIENT = Path("/usr/libexec/mano-stop")
STOP_STATE = Path("/var/lib/mano-stopd")
POLICY = Path("/etc/mano/human.uid")
PAM = Path("/etc/pam.d/mano-approve")
PROVIDER_POLICY = Path("/etc/mano/provider.json")
PRICING_POLICY = Path("/etc/mano/pricing.json")
CONTROLLER_POLICY = Path("/etc/mano/controller.json")
EGRESS_POLICY = Path("/etc/mano/egress.json")
PROVIDER_SECRETS = Path("/etc/mano/credentials")
PROVIDER_SOCKET = Path("/run/mano-provider/request.sock")
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
    "mano-core.slice",
    "mano-provider.socket",
    "mano-provider@.service",
    "mano-controller.service",
    "mano-controller.timer",
    "mano-egress.socket",
    "mano-egress@.service",
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
                           CONTROLLER_POLICY, EGRESS_POLICY,
                           LOCK, STOP_NATIVE, STOP_CLIENT, STOP_STATE, *SOCKETS.values())
)
assert all(not p.exists() for p in
           (PROVIDER_POLICY, PROVIDER_SECRETS, PROVIDER_SOCKET, PRICING_POLICY))
assert all(not (Path("/etc/systemd/system") / u).exists() for u in UNITS)
old_mode = STATE.parent.stat().st_mode & 0o777
installed = []
created_user = False
created_provider_user = False
created_egress_user = False
created_group = False
joined = False
identity = None
extra_gui_identities = []
pty_units = []
pty_frozen = None
pin_probe = None


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


def provider_idle_job():
    idle = subprocess.Popen(["/usr/sbin/runuser", "-u", "mano-broker", "--", "python3", "-c",
        "import socket,time;s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);"
        "s.connect('/run/mano-provider/request.sock');time.sleep(45)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        for child in Path("/sys/fs/cgroup/mano.slice/mano-core.slice").glob(
                "mano-provider@*.service"):
            try:
                pids = [int(pid) for pid in (child / "cgroup.procs").read_text().split()]
            except FileNotFoundError:
                continue
            if pids:
                # Type=exec starts RuntimeMaxSec only after successful exec.
                # A cgroup PID can still be systemd's pre-exec startup child.
                status = dict(line.split("=", 1) for line in command("systemctl", "show",
                    child.name, "--property=ActiveState", "--property=SubState",
                    "--property=MainPID").splitlines() if "=" in line)
                if (status.get("ActiveState") == "active" and status.get("SubState") == "running"
                        and len(pids) == 1 and status.get("MainPID") == str(pids[0])):
                    return idle, child.name, pids
        time.sleep(0.05)
    idle.terminate()
    idle.wait(timeout=3)
    raise AssertionError("Provider job not active")





def native_key_setup(value=None):
    answers = () if value is None else ((b'Provider API key:', value), (b'Confirm API key:', value))
    return native_terminal('mano_broker.provider_setup', answers=answers)


native_client = """import json,sys
from mano_prompt.approve import (rpc,view_packet,confirmation_packet,
 rearm_view_packet,rearm_confirmation_packet)
from mano_prompt.submit import prompt_packet
from mano_prompt.intake import read_status
from mano_prompt.task_status import read_task_status
from mano_prompt.mode import read_profile_status
body=json.loads(sys.stdin.read())
try:
 if body['mode']=='submit_prompt':result=rpc(prompt_packet(body['prompt'],body['key']))
 elif body['mode']=='prompt_status':
  result=dict(schema_version='1.0',ok=True,prompt=read_status(body['id']))
 elif body['mode']=='permission_status':result=read_profile_status(body['id'])
 elif body['mode']=='task_status':
  result=dict(schema_version='1.0',ok=True,snapshot=read_task_status(body['id']))
 elif body['mode']=='raw_prompt':result=rpc(bytes.fromhex(body['wire']))
 elif body['mode']=='view':result=rpc(view_packet(body['id']))
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
    subprocess.run(["useradd", "--system", "--user-group", "--no-create-home",
        "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "mano-provider"], check=True)
    created_provider_user = True
    subprocess.run(["useradd", "--system", "--user-group", "--no-create-home",
        "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "mano-egress"], check=True)
    created_egress_user = True
    provider_uid = pwd.getpwnam("mano-provider").pw_uid
    account = pwd.getpwnam("mano-broker")
    broker_uid = account.pw_uid
    assert broker_uid not in {0, 1001, 1002, 1003, 1004}
    subprocess.run(["usermod", "-a", "-G", "mano-request", "mano-worker"], check=True)
    joined = True
    CODE.mkdir(mode=0o755)
    for package in ("mano_broker", "mano_prompt", "mano_lab", "mano_core", "mano_protocol",
                    "mano_provider", "mano_egress"):
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
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", str(ROOT / "native/mano_stop.c"),
        "-Wl,-z,relro,-z,now", "-o", str(STOP_CLIENT)], check=True)
    STOP_CLIENT.chmod(0o555)
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
    PROVIDER_POLICY.write_text(json.dumps(dict(provider="openai", model="ci-health-snapshot",
        max_output_tokens=100, enabled=False)))
    PROVIDER_POLICY.chmod(0o600)
    shutil.copyfile(ROOT / "packaging/config/pricing.json", PRICING_POLICY)
    PRICING_POLICY.chmod(0o600)
    shutil.copyfile(ROOT / "packaging/config/controller.json", CONTROLLER_POLICY)
    CONTROLLER_POLICY.chmod(0o600)
    shutil.copyfile(ROOT / "packaging/config/egress.json", EGRESS_POLICY)
    EGRESS_POLICY.chmod(0o600)
    PROVIDER_SECRETS.mkdir(mode=0o700)
    (PROVIDER_SECRETS / "openai").write_text("ci-synthetic-provider-key")
    (PROVIDER_SECRETS / "openai").chmod(0o600)
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
    controller_tmpfiles = Path("/etc/tmpfiles.d/mano-controller.conf")
    assert not controller_tmpfiles.exists()
    shutil.copyfile(ROOT / "packaging/tmpfiles/mano-controller.conf", controller_tmpfiles)
    installed.append(controller_tmpfiles)
    subprocess.run(["systemd-tmpfiles", "--create", str(controller_tmpfiles)], check=True)
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
            "mano-provider.socket",
            "mano-egress.socket",
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
    price_probe = """from mano_broker.price_config import load_policy
from mano_broker.state import Denied
try:load_policy(wall_time=100)
except Denied as error:
 assert str(error)=='Root model pricing policy disabled'
 print('disabled-root-price-policy')
else:raise AssertionError('pricing unexpectedly enabled')
"""
    def broker_price_snapshot():
        result = subprocess.run(["/usr/bin/nsenter", "--target", str(pid), "--mount", "--",
            "/usr/sbin/runuser", "-u", "mano-broker", "--", "env",
            "PYTHONPATH=/usr/lib/mano-os",
            "CREDENTIALS_DIRECTORY=/run/credentials/mano-broker.service",
            "python3", "-c", price_probe], capture_output=True, text=True, timeout=10, check=True)
        assert result.stdout.strip() == "disabled-root-price-policy"
    broker_price_snapshot()
    # Root source edits do not mutate systemd's already-loaded credential snapshot.
    PRICING_POLICY.write_text(json.dumps(dict(schema_version="1.0", provider="openai", enabled=True,
        price=dict(model="synthetic", revision="ci-only", expires_unix=1000,
            input_context_tokens=1000, max_output_tokens=100,
            input_micro_usd_per_million=1001, output_micro_usd_per_million=2001))))
    broker_price_snapshot()
    shutil.copyfile(ROOT / "packaging/config/pricing.json", PRICING_POLICY)
    PRICING_POLICY.chmod(0o600)
    provider_packet = dict(schema_version="1.0", operation="health", body={})
    provider_result = subprocess.run(["/usr/sbin/runuser", "-u", "mano-broker", "--",
        "python3", "-c", client, str(PROVIDER_SOCKET), str(provider_uid), "-"],
        input=json.dumps(provider_packet), capture_output=True, text=True, timeout=10, check=True)
    provider_reply = json.loads(provider_result.stdout)
    assert provider_reply["sender_uid"] == provider_uid and provider_reply["creator_uid"] == 0
    assert provider_reply["payload"] == dict(schema_version="1.0", ok=True, provider="openai",
        model="ci-health-snapshot", credentials_present=True, execution_enabled=False)
    disabled_request = dict(schema_version="1.0", operation="generate", body={})
    disabled_provider = subprocess.run(["/usr/sbin/runuser", "-u", "mano-broker", "--",
        "python3", "-c", client, str(PROVIDER_SOCKET), str(provider_uid), "-"],
        input=json.dumps(disabled_request), capture_output=True, text=True, timeout=10, check=True)
    assert json.loads(disabled_provider.stdout)["payload"] == dict(
        schema_version="1.0", ok=False, error="denied")
    for actor in ("mano-agent", "mano-core", "mano-worker", "mano-human"):
        negative_provider = subprocess.run(["/usr/sbin/runuser", "-u", actor, "--", "python3",
            "-c", client, str(PROVIDER_SOCKET), str(provider_uid), "-"],
            input=json.dumps(provider_packet), capture_output=True, text=True, timeout=5,
            check=True)
        assert json.loads(negative_provider.stdout) == {"kernel_errno": "EACCES"}
        secret_denial = subprocess.run(["/usr/sbin/runuser", "-u", actor, "--", "python3", "-c",
            "from pathlib import Path\n"
            "try:Path('/etc/mano/credentials/openai').read_bytes()\n"
            "except PermissionError:pass\nelse:raise AssertionError('credential read')"],
            capture_output=True, text=True, timeout=5, check=True)
    egress_disabled_probe = """import socket
from mano_protocol.transport import CREDENTIALS,Peer
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(10);s.connect('/run/mano-egress/tls.sock')
 peer=Peer(*CREDENTIALS.unpack(s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,CREDENTIALS.size)))
 assert peer.pid>0 and peer.uid==0 and peer.gid==0
 assert s.recv(1)==b''
print('root-egress-closed')
"""
    egress_denial = subprocess.run(["/usr/sbin/runuser", "-u", "mano-provider", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", egress_disabled_probe],
        capture_output=True, text=True, timeout=15, check=True)
    assert egress_denial.stdout.strip() == "root-egress-closed"
    assert "egress-request-denied code=policy-disabled" in command("journalctl", "-u",
        "mano-egress@*.service", "-o", "cat", "--no-pager")
    wrong_egress = subprocess.run(["/usr/sbin/runuser", "-u", "mano-agent", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", egress_disabled_probe],
        capture_output=True, text=True, timeout=5, check=False)
    assert wrong_egress.returncode != 0 and "PermissionError" in wrong_egress.stderr
    EGRESS_POLICY.write_text(json.dumps(dict(schema_version="1.0", enabled=True)))
    EGRESS_POLICY.chmod(0o600)
    egress_tls_probe = """import ssl,time
from mano_provider.https import PinnedHTTPS
c=PinnedHTTPS(time.monotonic()+30)
try:
 c.connect()
 assert c.sock.context.check_hostname and c.sock.context.verify_mode==ssl.CERT_REQUIRED
 assert c.sock.getpeercert()
 print('fixed-provider-tls-handshake-only')
finally:c.close()
"""
    tls_handshake = subprocess.run(["/usr/sbin/runuser", "-u", "mano-provider", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", egress_tls_probe],
        capture_output=True, text=True, timeout=35, check=True)
    assert tls_handshake.stdout.strip() == "fixed-provider-tls-handshake-only"
    shutil.copyfile(ROOT / "packaging/config/egress.json", EGRESS_POLICY)
    EGRESS_POLICY.chmod(0o600)
    provider_timer_client, provider_timer_unit, provider_timer_pids = provider_idle_job()
    provider_started = time.monotonic()
    try:
        subprocess.run(["kill", "-STOP", *(str(pid) for pid in provider_timer_pids)], check=True)
        provider_deadline = provider_started + 38
        while time.monotonic() < provider_deadline:
            result = command("systemctl", "show", provider_timer_unit,
                             "--property=Result", "--value")
            exit_status = command("systemctl", "show", provider_timer_unit,
                                  "--property=ExecMainStatus", "--value")
            if result == "timeout" and exit_status == "9":
                break
            time.sleep(0.1)
        assert result == "timeout", result
        provider_deadline_seconds = time.monotonic() - provider_started
        assert command("systemctl", "show", provider_timer_unit,
                       "--property=ExecMainStatus", "--value") == "9", exit_status
    finally:
        provider_timer_client.terminate()
        provider_timer_client.wait(timeout=3)
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
        # Recovery is independent of file effects. Both READ and WRITE now
        # execute, so use the existing non-dispatched health-inspection intent.
        capability="system.inspect_health",
        args={},
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
    # Keep a genuine native-library pin/rename test under the actual broker UID.
    # This is a separately Root-supervised probe, not a claim that the health
    # intent pins a file or that the daemon retains completed-write leases.
    pin_program = """import hashlib,json,os,sys
from mano_broker.resources import Workspace
fd=os.open(sys.argv[1],os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
with Workspace(fd) as workspace:
 os.close(fd)
 with workspace.pin('file') as pin:
  print(json.dumps(dict(pid=os.getpid(),fd=pin.fd,inode=pin.inode,device=pin.device)),flush=True)
  assert sys.stdin.readline()=='inspect\\n'
  source=pin.read_fd()
  try:data=os.read(source,32768)
  finally:os.close(source)
  print(json.dumps(dict(sha256=hashlib.sha256(data).hexdigest())),flush=True)
"""
    pin_probe = subprocess.Popen(["/usr/sbin/runuser", "-u", "mano-broker", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", pin_program, str(WORK)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pin_ready = json.loads(pin_probe.stdout.readline())
    inode = target.stat().st_ino
    original_digest = hashlib.sha256(target.read_bytes()).hexdigest()
    assert pin_ready["inode"] == inode and pin_ready["device"] == target.stat().st_dev
    actual_pin = Path(f"/proc/{pin_ready['pid']}/fd/{pin_ready['fd']}")
    assert actual_pin.stat().st_ino == inode
    target.rename(WORK / "retained")
    target.symlink_to("/etc/mano/sentinel")
    assert actual_pin.stat().st_ino == inode
    pin_out, pin_error = pin_probe.communicate(input="inspect\n", timeout=5)
    assert pin_probe.returncode == 0, pin_error
    assert json.loads(pin_out)["sha256"] == original_digest
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
    restart_profile = proposal | dict(capability="policy.set_profile",
        args=dict(mode="supervised", duration_seconds=300, max_actions=2, max_timeout_seconds=10),
        idempotency_key="active-profile-before-restart")
    restart_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
                                          body=restart_profile))["approval"]
    restart_view = human(dict(mode="view", id=restart_pending["approval_id"]))["view"]
    restart_origin = human(dict(mode="confirm", view=restart_view, password=password))["grant_id"]
    restart_read = proposal | dict(capability="files.read", args=dict(path="retained"),
        idempotency_key="profile-unused-grant-before-restart")
    restart_auto = rpc("request", dict(schema_version="1.0", operation="request_approval",
                                       body=restart_read))["approval"]
    assert restart_auto["state"] == "approved"
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        live_lease = database.execute('SELECT remaining,expires FROM task_profiles WHERE task_id=?',
                                      (proposal["task_id"],)).fetchone()
        live_grant = database.execute('SELECT expires,revoked,used FROM grants WHERE id=?',
                                      (restart_auto["grant_id"],)).fetchone()
        assert live_lease[0] == 1 and live_lease[1] > time.monotonic()
        assert live_grant[0] > time.monotonic() and live_grant[1:] == (0, 0)
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
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        recovered_lease = database.execute(
            'SELECT remaining,expires FROM task_profiles WHERE task_id=?',
            (proposal["task_id"],)).fetchone()
        assert recovered_lease[0] == 0 and recovered_lease[1] > time.monotonic()
        assert database.execute('SELECT revoked FROM grants WHERE id=?',
                                (restart_origin,)).fetchone() == (1,)
        assert database.execute('SELECT expires FROM grants WHERE id=?',
                                (restart_auto["grant_id"],)).fetchone()[0] > time.monotonic()
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=restart_read | dict(grant_id=restart_auto["grant_id"]))) == denied
    after_restart = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=proposal | dict(capability="files.read", args=dict(path="retained"),
                             idempotency_key="profile-read-after-restart")))
    assert after_restart == denied  # Lost descriptors require fresh provisioning.
    assert human(dict(mode="confirm", view=restart_view, password=password)) == {"ok": False}
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
    prompt_request = dict(mode="submit_prompt", key="a" * 32,
                          prompt="Create and test a small addition project")
    human_receipt = human(prompt_request)
    assert human_receipt["ok"] and human_receipt["prompt"]["state"] == "received"
    assert human_receipt["prompt"]["task_id"] is None
    assert human(prompt_request) == human_receipt
    assert human(dict(mode="prompt_status", id=human_receipt["prompt"]["id"])) == human_receipt
    for wire in (b"\x01\x05" + b"b" * 32 + b"\x00\x02x",
                 b"\x01\x05" + b"b" * 32 + b"\x00\x01\xff"):
        assert human(dict(mode="raw_prompt", wire=wire.hex()))["ok"] is False
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        assert human(prompt_request, actor=actor)["ok"] is False
    assert rpc("request", dict(schema_version="1.0", operation="submit_prompt",
        body=dict(human_uid=1002, request_key="b" * 32, prompt="forged human"))) == denied
    default_prompt_code = """import json
from mano_prompt.app import Prompt
from mano_prompt.submit import status_packet
from mano_prompt.approve import rpc
app=Prompt()
receipt=app.submit('Default human prompt production transport')
assert receipt['state']=='received' and receipt['task_id'] is None
assert rpc(status_packet(receipt['id']))['prompt']==receipt
print(json.dumps(dict(default_handler_native_ack=True,task_id=None)))
"""
    default_prompt = subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "python3", "-c",
        default_prompt_code], capture_output=True, text=True, timeout=10, check=False)
    assert default_prompt.returncode == 0, default_prompt.stderr
    assert json.loads(default_prompt.stdout)["default_handler_native_ack"] is True
    discovery = dict(schema_version="1.0", operation="pending_prompts",
                     body=dict(human_uid=1002))
    queued = rpc("control", discovery, actor="root")["prompts"]
    assert human_receipt["prompt"] in queued
    assert all(set(item) == {"id", "state", "task_id"}
               and item["state"] == "received" and item["task_id"] is None for item in queued)
    assert rpc("request", discovery) == denied
    factory_result = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
        "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.task_factory"],
        input=json.dumps(dict(prompt_id=human_receipt["prompt"]["id"])),
        capture_output=True, text=True, timeout=25, check=False)
    assert factory_result.returncode == 0, (factory_result.stdout[-1024:],
                                           factory_result.stderr[-4096:])
    managed = json.loads(factory_result.stdout)
    assert managed["ok"]
    managed = managed["task"]
    planner_managed = managed | {"context": managed["context"] | {
        "operation_key": "ci-broker-planner-witness"}}
    for _ in range(2):
        planner_result = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.lifecycle",
            "--broker-model"], input=json.dumps(dict(managed=planner_managed,
                model=dict(model="synthetic-snapshot", max_output_tokens=100))),
            capture_output=True, text=True, timeout=15, check=True)
        planned = json.loads(planner_result.stdout)
        assert planned["ok"] and planned["task"]["status"] == "awaiting_model_grant"
        assert all(planned["task"][key] == value
                   for key, value in planner_managed["context"].items())
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        disclosures = [json.loads(row[0]) for row in database.execute(
            "SELECT proposal_json FROM approvals WHERE task_id=?",
            (managed["context"]["task_id"],))]
        assert sum(item["capability"] == "model.plan" for item in disclosures) == 1
        assert database.execute("SELECT count(*) FROM grants WHERE task_id=? "
            "AND capability='model.plan'", (managed["context"]["task_id"],)).fetchone() == (0,)
        assert database.execute("SELECT count(*) FROM provider_jobs").fetchone() == (0,)
    account = pwd.getpwuid(managed["caller_uid"])
    assert account.pw_name == managed["caller_name"]
    identity = TaskIdentity(account.pw_name, account.pw_uid, account.pw_gid)
    terminal_workspace = Path(managed["workspace"])
    delegate_authorization = os.open(terminal_workspace / ".delegate-ci-authorized",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    with os.fdopen(delegate_authorization, "wb") as stream:
        os.fchmod(stream.fileno(), 0o640)
        os.fchown(stream.fileno(), 0, identity.gid)
        stream.write(b"mano-phase0-ci-delegates\n")
    delegate_unit = "mano-delegate-contract-" + secrets.token_hex(6)
    pty_units.append(delegate_unit + ".service")
    global_delegate_settings = Path("/home/mano-human/.gemini/antigravity-cli/settings.json")
    assert not global_delegate_settings.exists()
    global_delegate_settings.parent.mkdir(parents=True, mode=0o700)
    global_delegate_settings.write_text('{"mano_ci_global_sentinel":"must remain unchanged"}\n')
    global_delegate_digest = hashlib.sha256(global_delegate_settings.read_bytes()).hexdigest()
    host_loopback = socket.socket()
    host_loopback.bind(("127.0.0.1", 0))
    host_loopback.listen(1)
    try:
        delegate_probe = subprocess.run(["systemd-run", "--quiet", "--pipe", "--wait", "--collect",
        "--unit=" + delegate_unit, "--uid=" + identity.name, "--slice=mano-core.slice",
        "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=", "--property=MemoryMax=512M", "--property=TasksMax=48",
        "--property=CPUQuota=50%", "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=1",
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
        "--property=ReadWritePaths=" + str(terminal_workspace), "--property=PrivateTmp=yes",
        "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8",
        "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3",
        str(ROOT / "scripts/probe_coding_delegates.py"), str(terminal_workspace),
        str(host_loopback.getsockname()[1])],
        text=True, capture_output=True, timeout=150, check=False)
    finally:
        host_loopback.close()
    delegate_probe_passed = delegate_probe.returncode == 0
    assert (hashlib.sha256(global_delegate_settings.read_bytes()).hexdigest()
            == global_delegate_digest)
    delegate_contracts = json.loads(delegate_probe.stdout)
    delegate_contracts["host_global_settings_unchanged"] = True
    assert len(delegate_probe.stdout.encode()) < 65536
    (ROOT / "evidence/coding-delegate-contracts.json").write_text(
        json.dumps(delegate_contracts, indent=2) + "\n")
    terminal_task = dict(ok=True, task_id=managed["context"]["task_id"],
                         resource_id=managed["context"]["resource_id"])
    attached_status = human(dict(mode="prompt_status", id=human_receipt["prompt"]["id"]))
    assert attached_status["prompt"]["state"] == "task_created"
    assert attached_status["prompt"]["task_id"] == terminal_task["task_id"]
    assert human_receipt["prompt"]["id"] not in {
        item["id"] for item in rpc("control", discovery, actor="root")["prompts"]}
    queue_cycle = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
        "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.lifecycle", "--mock"],
        input=json.dumps(dict(next_prompt=True, plan=dict(args=dict(
            argv=["/usr/bin/true"], cwd=".", timeout_seconds=1), reason="Queue cycle witness"))),
        capture_output=True, text=True, timeout=35, check=False)
    assert queue_cycle.returncode == 0, queue_cycle.stderr
    queue_task = json.loads(queue_cycle.stdout)["task"]
    assert queue_task["status"] == "awaiting_grant"
    assert queue_task["task_id"] != terminal_task["task_id"]
    assert rpc("control", discovery, actor="root")["prompts"] == []
    controller_receipt = human(dict(mode="submit_prompt", key="d" * 32,
        prompt="Controller checkpoint and disclosure approval witness"))
    assert controller_receipt["ok"]
    controller_tasks = []
    for cycle_index in range(2):
        if cycle_index:
            time.sleep(5.1)  # Broker-owned minimum interval, not a retry of an uncertain effect.
        controller_result = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.controller",
            "--model", "synthetic-snapshot", "--max-output-tokens", "100"],
            capture_output=True, text=True, timeout=35, check=True)
        controller_value = json.loads(controller_result.stdout)
        assert controller_value["ok"]
        cycle = controller_value["cycle"]
        assert cycle["prompt_id"] == controller_receipt["prompt"]["id"]
        assert cycle["status"] == "awaiting_model_grant"
        controller_tasks.append(cycle["task_id"])
    assert controller_tasks[0] == controller_tasks[1]
    controller_status = human(dict(mode="prompt_status", id=controller_receipt["prompt"]["id"]))
    assert controller_status["prompt"]["task_id"] == controller_tasks[0]
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute("SELECT state,status FROM core_cycles WHERE prompt_id=?",
            (controller_receipt["prompt"]["id"],)).fetchone() == (
                "waiting", "awaiting_model_grant")
        assert database.execute("SELECT count(*) FROM grants WHERE task_id=?",
                                (controller_tasks[0],)).fetchone() == (0,)
        assert database.execute("SELECT count(*) FROM provider_jobs").fetchone() == (0,)
    subprocess.run(["systemctl", "start", "mano-controller.service"],
                   capture_output=True, text=True, timeout=45, check=True)
    assert command("systemctl", "show", "mano-controller.service",
                   "--property=ExecMainStatus", "--value").strip() == "0"
    assert '"state":"disabled"' in command("journalctl", "-u", "mano-controller.service",
                                               "-o", "cat", "--no-pager")
    CONTROLLER_POLICY.write_text(json.dumps(dict(schema_version="1.0", enabled=True,
        model="synthetic-snapshot", max_output_tokens=100)))
    CONTROLLER_POLICY.chmod(0o600)
    service_receipt = human(dict(mode="submit_prompt", key="e" * 32,
        prompt="Recurring controller service approval witness"))
    assert service_receipt["ok"]
    subprocess.run(["systemctl", "start", "mano-controller.service"],
                   capture_output=True, text=True, timeout=45, check=True)
    service_prompt = service_receipt["prompt"]["id"]
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        original_cycle = database.execute("SELECT nonce,state,status FROM core_cycles "
            "WHERE prompt_id=?", (service_prompt,)).fetchone()
        original_task = database.execute("SELECT task_id FROM human_prompts WHERE id=?",
                                         (service_prompt,)).fetchone()[0]
    assert original_cycle[1:] == ("waiting", "awaiting_model_grant")
    subprocess.run(["systemctl", "start", "mano-controller.timer"], check=True)
    deadline = time.monotonic() + 35
    repeated_cycle = original_cycle
    while time.monotonic() < deadline:
        with contextlib.closing(sqlite3.connect(
                f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
            repeated_cycle = database.execute("SELECT nonce,state,status FROM core_cycles "
                "WHERE prompt_id=?", (service_prompt,)).fetchone()
        if repeated_cycle[0] != original_cycle[0] and repeated_cycle[1:] == (
                "waiting", "awaiting_model_grant"):
            break
        time.sleep(0.25)
    subprocess.run(["systemctl", "stop", "mano-controller.timer", "mano-controller.service"],
                   capture_output=True, text=True, timeout=5, check=True)
    assert repeated_cycle[0] != original_cycle[0]
    assert repeated_cycle[1:] == ("waiting", "awaiting_model_grant")
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute("SELECT task_id FROM human_prompts WHERE id=?",
                                (service_prompt,)).fetchone() == (original_task,)
        assert database.execute("SELECT count(*) FROM grants WHERE task_id=?",
                                (original_task,)).fetchone() == (0,)
        assert database.execute("SELECT count(*) FROM provider_jobs").fetchone() == (0,)
    shutil.copyfile(ROOT / "packaging/config/controller.json", CONTROLLER_POLICY)
    CONTROLLER_POLICY.chmod(0o600)
    duplicate_creation = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
        "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.task_factory"],
        input=json.dumps(dict(prompt_id=human_receipt["prompt"]["id"])),
        capture_output=True, text=True, timeout=5, check=False)
    assert duplicate_creation.returncode == 1
    assert json.loads(duplicate_creation.stdout)["ok"] is False
    budget_proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
        resource_id=terminal_task["resource_id"], capability="model.set_budget",
        args=dict(money_micro_usd=100, tokens=1000), idempotency_key="task-model-budget",
        reason="Synthetic task spending ceiling witness")
    budget_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=budget_proposal), actor=identity.name)["approval"]
    budget_view = human(dict(mode="view", id=budget_pending["approval_id"]))["view"]
    assert budget_view["capability"] == "model.set_budget"
    assert budget_view["args"] == budget_proposal["args"]
    assert human(dict(mode="confirm", view=budget_view, password="wrong-ci-password")) == {
        "ok": False}
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute("SELECT 1 FROM model_budgets WHERE task_id=?",
                                (terminal_task["task_id"],)).fetchone() is None
    budget_grant = human(dict(mode="confirm", view=budget_view, password=password))
    assert budget_grant["ok"]
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute("SELECT money_limit,token_limit FROM model_budgets WHERE task_id=?",
                                (terminal_task["task_id"],)).fetchone() == (100, 1000)
        assert database.execute("SELECT used FROM grants WHERE id=?",
                                (budget_grant["grant_id"],)).fetchone() == (1,)
    assert human(dict(mode="confirm", view=budget_view, password=password)) == {"ok": False}
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=budget_proposal | {"grant_id": budget_grant["grant_id"]}),
        actor=identity.name) == denied
    cloud_proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
        resource_id=terminal_task["resource_id"], capability="model.plan",
        args=dict(provider="openai", model="explicit-snapshot",
                  prompt=managed["context"]["prompt"], max_output_tokens=100),
        idempotency_key="cloud-disclosure-once", reason="Exact model disclosure witness")
    cloud_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=cloud_proposal), actor=identity.name)["approval"]
    cloud_view = human(dict(mode="view", id=cloud_pending["approval_id"]))["view"]
    assert cloud_view["capability"] == "model.plan"
    assert cloud_view["args"] == cloud_proposal["args"]
    assert human(dict(mode="confirm", view=cloud_view, password="wrong-ci-password")) == {
        "ok": False}
    cloud_grant = human(dict(mode="confirm", view=cloud_view, password=password))
    assert cloud_grant["ok"]
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=cloud_proposal | {"grant_id": cloud_grant["grant_id"]}), actor=identity.name) == denied
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute("SELECT used FROM grants WHERE id=?",
                                (cloud_grant["grant_id"],)).fetchone() == (0,)
        assert database.execute("SELECT count(*) FROM provider_jobs").fetchone() == (0,)
    terminal_proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
        resource_id=terminal_task["resource_id"], capability="terminal.run",
        args=dict(argv=["/usr/bin/python3", "-c",
            "from pathlib import Path;"
            "Path('/workspace/live-result').write_text('pam-terminal-ok')"],
            cwd=".", timeout_seconds=10), idempotency_key="pam-terminal-once",
        reason="actual PAM-bound terminal integration")
    terminal_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=terminal_proposal), actor=identity.name)["approval"]
    task_snapshot_query = dict(mode="task_status", id=human_receipt["prompt"]["id"])
    task_snapshot = human(task_snapshot_query)["snapshot"]
    assert task_snapshot["prompt"]["task_id"] == terminal_task["task_id"]
    assert task_snapshot["action_count"] == 0 and task_snapshot["actions"] == []
    assert any(item == dict(approval_id=terminal_pending["approval_id"],
        capability="terminal.run", state="pending") for item in task_snapshot["approvals"])
    for private in ("nonce", "grant_id", "operation_digest", "args", "reason_untrusted",
                    "pam-terminal-ok"):
        assert private not in json.dumps(task_snapshot)
    for actor in ("mano-agent", "mano-core", "mano-worker", identity.name):
        assert human(task_snapshot_query, actor=actor) == {"ok": False}
    cross_human = dict(schema_version="1.0", operation="human_task_status", body=dict(
        human_uid=pwd.getpwnam("mano-worker").pw_uid, prompt_id=human_receipt["prompt"]["id"]))
    assert rpc("control", cross_human, actor="root") == denied
    malformed_status = b"\x01\x07" + human_receipt["prompt"]["id"].encode() + b"extra"
    assert human(dict(mode="raw_prompt", wire=malformed_status.hex())) == {"ok": False}
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
    completed_snapshot = human(task_snapshot_query)["snapshot"]
    assert any(item == dict(action_id=terminal_action["action"]["id"],
        capability="terminal.run", state="done", effect_verified=False)
        for item in completed_snapshot["actions"])
    assert any(item["approval_id"] == terminal_pending["approval_id"]
               and item["state"] == "approved" for item in completed_snapshot["approvals"])
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
    agent_program = (
        "from pathlib import Path;import subprocess,sys;"
        "Path('/workspace/calc.py').write_text('def add(a,b): return a+b\\n');"
        "Path('/workspace/test_calc.py').write_text('import unittest\\nfrom calc import add\\n'"
        "+'class TestAdd(unittest.TestCase):\\n'"
        "+' def test_add(self): self.assertEqual(add(2,3),5)\\n');"
        "p=subprocess.run([sys.executable,'-m','unittest','-q'],cwd='/workspace');"
        "Path('/workspace/golden-result').write_text('tests-passed' if p.returncode==0 "
        "else 'tests-failed');sys.exit(p.returncode)"
    )
    agent_step_code = """import json,sys
from pathlib import Path
from mano_core.broker import BrokerClient
from mano_core.runtime import AgentRuntime
from mano_core.checkpoints import Session
body=json.load(sys.stdin)
fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines()
            if ':' in line)
assert all(int(fields[k].strip(),16)==0 for k in ('CapEff','CapBnd','CapAmb'))
assert fields['NoNewPrivs'].strip()=='1' and fields['Seccomp'].strip()=='2'
group=Path('/sys/fs/cgroup')/next(line.split('::',1)[1].lstrip('/')
    for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
assert (group/'memory.max').read_text().strip()=='268435456'
assert (group/'pids.max').read_text().strip()=='32'
assert (group/'cpu.max').read_text().strip()=='50000 100000'
def mock_model(prompt):
 assert prompt=='Create and test a small addition project'
 return dict(args=body['args'],reason='Create and run golden project unit test')
client=BrokerClient()
try:
 if body['persistent']:
  session=Session(body['checkpoint_directory'],mock_model,client)
  try:
   context={k:body['state'][k] for k in ('task_id','resource_id','operation_key','prompt')}
   result=session.step(context)
  finally:session.close()
 else:
  result=AgentRuntime(mock_model,client).step(body['state'],thread_id=body['state']['task_id'])
 print(json.dumps(result))
finally:client.close()
"""

    def agent_step(state, *, persistent=True):
        checkpoint_directory = str(terminal_workspace / ".mano-agent")
        plan_args = dict(argv=["/usr/bin/python3", "-c", agent_program],
                         cwd=".", timeout_seconds=10)
        if persistent:
            lifecycle = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
                "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.lifecycle", "--mock"],
                input=json.dumps(dict(prompt_id=managed["prompt_id"],
                    plan=dict(args=plan_args, reason="Create and run golden project unit test"))),
                capture_output=True, text=True, timeout=15, check=False)
            assert lifecycle.returncode == 0, lifecycle.stderr
            decoded = json.loads(lifecycle.stdout)
            assert decoded["ok"]
            return decoded["task"]
        else:
            entry = ["-c", agent_step_code]
            payload = dict(state=state, persistent=False, checkpoint_directory=checkpoint_directory,
                           args=plan_args)
        result = subprocess.run(["systemd-run", "--quiet", "--wait", "--pipe", "--collect",
            "--unit=mano-agent-step-" + str(time.monotonic_ns()), "--uid=" + identity.name,
            "--slice=mano-core.slice",
            "--property=MemoryMax=256M", "--property=TasksMax=32", "--property=CPUQuota=50%",
            "--property=RuntimeMaxSec=8", "--property=TimeoutStopSec=1",
            "--property=LimitNOFILE=128", "--property=SystemCallArchitectures=native",
            "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
            "--property=AmbientCapabilities=", "--property=ProtectSystem=strict",
            "--property=ReadWritePaths=" + str(terminal_workspace),
            "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
            "--property=RestrictNamespaces=yes", "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=SystemCallFilter=@system-service", "--property=SystemCallErrorNumber=EPERM",
            "--property=MemoryDenyWriteExecute=yes", "env",
            "PYTHONPATH=/usr/lib/mano-os:/usr/lib/mano-runtime/vendor",
            "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", *entry],
            input=json.dumps(payload), capture_output=True,
            text=True, timeout=10, check=False)
        if result.returncode != 0:
            raise AssertionError("Fixed CI mock core step failed: " + result.stderr[-4096:])
        decoded = json.loads(result.stdout)
        if persistent:
            assert decoded["ok"] is True
            return decoded["task"]
        return decoded

    agent_state = agent_step(managed["context"])
    assert agent_state["status"] == "awaiting_grant"
    assert not (terminal_workspace / "calc.py").exists()
    expected_source = b"def add(a,b): return a+b\n"
    declared = rpc("control", dict(schema_version="1.0", operation="declare_artifact_contract",
        body=dict(approval_id=agent_state["approval_id"], path="calc.py",
                  sha256=hashlib.sha256(expected_source).hexdigest(), size=len(expected_source))),
        actor="root")
    assert declared["ok"]
    agent_view = human(dict(mode="view", id=agent_state["approval_id"]))["view"]
    assert human(dict(mode="confirm", view=agent_view, password=password))["ok"]
    agent_pending = dict(agent_state)
    agent_state = agent_step(agent_state)
    agent_action_id = agent_state["action_id"]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and agent_state["status"] in {"queued", "running"}:
        time.sleep(0.1)
        agent_state = agent_step(agent_state)
    assert agent_state["status"] == "verifying", agent_state["status"]
    assert (terminal_workspace / "golden-result").read_text() == "tests-passed"
    assert (terminal_workspace / "calc.py").exists()
    (terminal_workspace / "golden-result").write_text("replay-canary")
    agent_replay = agent_step(agent_pending, persistent=False)
    assert agent_replay["action_id"] == agent_action_id
    assert agent_replay["status"] == "verifying"
    assert (terminal_workspace / "golden-result").read_text() == "replay-canary"
    source_artifact = rpc("control", dict(schema_version="1.0", operation="capture_artifact",
        body=dict(action_id=agent_action_id, path="calc.py")), actor="root")["artifact"]
    verifier_body = dict(action_id=agent_action_id, artifact_id=source_artifact["artifact_id"])
    assert rpc("request", dict(schema_version="1.0", operation="check_artifact_contract",
        body=verifier_body), actor=identity.name) == denied
    assert rpc("control", dict(schema_version="1.0", operation="check_artifact_contract",
        body=verifier_body | {"artifact_id": captured["artifact"]["artifact_id"]}),
        actor="root") == denied
    checked = rpc("control", dict(schema_version="1.0", operation="check_artifact_contract",
        body=verifier_body), actor="root")
    assert checked["ok"] and checked["verification"]["predicate"] == "exact-file-v1"
    verified_snapshot = human(task_snapshot_query)["snapshot"]
    assert any(item["action_id"] == agent_action_id and item["state"] == "done"
               and item["effect_verified"] is True for item in verified_snapshot["actions"])
    assert agent_step(agent_state)["status"] == "completed"
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
        installed_active_profile_lease_restart_revoked=True,
        native_pam_grant=True, wrong_password_no_effect=True, changed_arguments_denied=True,
        durable_terminal_done=True,
        workspace_effect_observed=True, effect_verified=False, replay_no_execution=True,
        wrong_caller_status_denied=True, physical_input_provenance=None,
        production_broker_sealed_capture=True, actual_task_artifact_read=True,
        langgraph_actual_task_peer=True, mock_agent_golden_project_tests=True,
        mock_agent_pam_grant=True, mock_agent_replay_same_action=True,
        mock_agent_replay_no_effect=True,
        sqlite_agent_checkpoint_new_process_recovery=True,
        installed_core_cli_entrypoint=True,
        installed_broker_planner_core_entrypoint=True,
        installed_durable_controller_cycle=True,
        installed_recurring_controller_service=True,
        controller_root_policy_and_network_kernel_denials=True,
        controller_provider_key_source_hidden=True,
        installed_egress_disabled_policy_denied=True,
        egress_wrong_uid_and_provider_key_source_denied=True,
        fixed_provider_unix_tls_handshake_without_http=True,
        installed_bounded_lifecycle_controller=True,
        durable_prompt_context_dispatch_reused=True,
        installed_root_task_factory=True,
        authenticated_native_human_prompt_queue=True,
        read_only_intake_client_actual_native_transport=True,
        human_task_snapshot_pending_done_scope_and_redaction=True,
        default_prompt_handler_actual_native_transport=True,
        protected_pending_prompt_discovery=True,
        installed_bounded_queue_cycle=True,
        native_pam_task_model_budget=True,
        budget_grant_replay_and_public_dispatch_denied=True,
        native_pam_model_disclosure_grant=True,
        installed_disabled_model_policy_preserves_grant=True,
        human_prompt_claim_to_actual_task=True,
        prompt_creation_replay_denied=True,
        prompt_duplicate_and_malformed_cases_verified=True,
        prompt_untrusted_sender_and_public_route_denied=True,
        core_step_cgroup_and_capability_limits_verified=True,
        mock_agent_exit_alone_unverified=True, preapproval_exact_file_predicate=True,
        verifier_public_and_wrong_action_denied=True,
        artifact_capture_request_denied=True, artifact_wrong_caller_and_range_denied=True)
    client_contract = subprocess.run(["unshare", "--mount", "--propagation", "private",
        "python3", str(ROOT / "tests/desktop/stop_client_contract.py")],
        capture_output=True, text=True, check=True, timeout=20)
    assert set(json.loads(client_contract.stdout)["reply_cases"]) == {
        "valid", "denied", "extra", "truncated", "rights", "wrong_sender", "wrong_creator",
        "timeout"}
    terminal_report["native_stop_client_reply_contract"] = True
    terminal_report["native_stop_client_reply_cases"] = json.loads(client_contract.stdout)
    subprocess.run(["systemctl", "start", "mano-stopd.socket", "mano-stopd.service"], check=True)
    stop_pid = int(command(
        "systemctl", "show", "mano-stopd.service", "--property=MainPID", "--value"
    ))
    stop_fields = dict(line.split(":", 1) for line in Path(f"/proc/{stop_pid}/status").read_text()
                       .splitlines() if ":" in line)
    assert int(stop_fields["CapEff"].strip(), 16) == 0
    assert stop_fields["NoNewPrivs"].strip() == "1" and stop_fields["Seccomp"].strip() == "2"
    def install_profile(mode, *, operator_password, count=2, duration=60):
        policy = dict(schema_version="1.0", task_id=terminal_task["task_id"],
            resource_id=terminal_task["resource_id"], capability="policy.set_profile",
            args=dict(mode=mode, duration_seconds=duration, max_actions=count,
                      max_timeout_seconds=10), idempotency_key="profile-" + secrets.token_hex(8),
            reason="Synthetic native PAM workspace profile witness")
        pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
                                      body=policy), actor=identity.name)["approval"]
        assert pending["state"] == "pending" and pending["grant_id"] is None
        view = human(dict(mode="view", id=pending["approval_id"]))["view"]
        assert view["profile_scope"]["filesystem"] == "allocated task workspace only"
        assert view["profile_scope"]["network"] == "disabled"
        assert view["args"] == policy["args"]
        with contextlib.closing(sqlite3.connect(
                f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
            before_profile = database.execute('SELECT * FROM task_profiles WHERE task_id=?',
                                              (terminal_task["task_id"],)).fetchall()
        assert human(dict(mode="confirm", view=view, password="wrong-ci-password")) == {"ok": False}
        with contextlib.closing(sqlite3.connect(
                f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
            assert database.execute('SELECT * FROM task_profiles WHERE task_id=?',
                (terminal_task["task_id"],)).fetchall() == before_profile
        approved = human(dict(mode="confirm", view=view, password=operator_password))
        assert approved["ok"]
        return approved["grant_id"]

    def profiled_request(capability, args):
        proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
            resource_id=terminal_task["resource_id"], capability=capability, args=args,
            idempotency_key="profile-action-" + secrets.token_hex(8), reason="CI workspace lease")
        approved = rpc("request", dict(schema_version="1.0", operation="request_approval",
                                       body=proposal), actor=identity.name)["approval"]
        return proposal, approved

    install_profile("supervised", operator_password=password, count=1)
    read_proposal, read_approved = profiled_request("files.read", dict(path="live-result"))
    assert read_approved["state"] == "approved"
    file_request = dict(schema_version="1.0", operation="propose",
        body=read_proposal | dict(grant_id=read_approved["grant_id"]))
    file_action = rpc("request", file_request, actor=identity.name)["action"]["id"]
    file_query = dict(schema_version="1.0", operation="file_result", body=dict(
        task_id=terminal_task["task_id"], action_id=file_action, offset=0, length=4096))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        file_result = rpc("request", file_query, actor=identity.name)
        if file_result["ok"]:
            break
        time.sleep(0.1)
    assert file_result["ok"] and file_result["eof"], file_result
    assert base64.b64decode(file_result["data"], validate=True) == b"pam-terminal-ok"
    assert file_result["artifact"]["action_id"] == file_action
    assert file_result["artifact"]["effect_verified"] is False
    assert file_result["artifact"]["sha256"] == hashlib.sha256(b"pam-terminal-ok").hexdigest()
    # Retrieval is immutable and scoped, not another filesystem read or grant use.
    assert rpc("request", file_query) == denied
    for change in (dict(task_id="0" * 32), dict(action_id="0" * 32),
                   dict(offset=True), dict(length=4097), dict(offset=999)):
        assert rpc("request", file_query | dict(body=file_query["body"] | change),
                   actor=identity.name) == denied
    replayed_read = rpc("request", file_request, actor=identity.name)
    assert not replayed_read["fresh"] and replayed_read["action"]["state"] == "done"
    assert replayed_read["action"]["id"] == file_action
    assert replayed_read["action"]["verified"] == 0
    assert rpc("request", file_query, actor=identity.name) == file_result
    terminal_report["production_authorized_workspace_read_sealed_result"] = True
    terminal_report["file_read_result_scope_range_and_no_reexecution"] = True
    read_managed = managed | dict(context=managed["context"] | dict(
        operation_key="ci-typed-read-core-witness"))
    read_plan = dict(capability="files.read", args=dict(path="live-result"),
                     reason="Read the bounded local result without a terminal command")

    def typed_read_step():
        result = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.lifecycle", "--mock"],
            input=json.dumps(dict(managed=read_managed, plan=read_plan)),
            capture_output=True, text=True, timeout=15, check=False)
        assert result.returncode == 0, result.stderr[-4096:]
        decoded = json.loads(result.stdout)
        assert decoded["ok"], decoded
        return decoded["task"]

    typed_pending = typed_read_step()
    assert typed_pending["status"] == "awaiting_grant"
    assert typed_pending["proposal"]["capability"] == "files.read"
    read_view = human(dict(mode="view", id=typed_pending["approval_id"]))["view"]
    assert read_view["capability"] == "files.read" and read_view["args"] == read_plan["args"]
    assert human(dict(mode="confirm", view=read_view, password=password))["ok"]
    typed_ready = typed_read_step()
    deadline = time.monotonic() + 15
    while typed_ready["status"] in {"queued", "running"} and time.monotonic() < deadline:
        typed_ready = typed_read_step()  # Reopen private SQLite checkpoint in a new core process.
    assert typed_ready["status"] == "read_ready", typed_ready["status"]
    assert typed_ready["read_result"]["sha256"] == hashlib.sha256(b"pam-terminal-ok").hexdigest()
    assert typed_ready["read_result"]["effect_verified"] is False
    assert "pam-terminal-ok" not in json.dumps(typed_ready)  # Metadata only, never source bytes.
    assert rpc("request", dict(schema_version="1.0", operation="inspect_file_read", body=dict(
        task_id=terminal_task["task_id"], action_id=typed_ready["action_id"])),
        actor=identity.name) == denied
    original_read_source = (terminal_workspace / "live-result").read_bytes()
    try:
        (terminal_workspace / "live-result").write_bytes(b"changed-after-read-canary")
        typed_replay = typed_read_step()
        assert typed_replay["status"] == "read_ready"
        assert typed_replay["action_id"] == typed_ready["action_id"]
        assert typed_replay["read_result"] == typed_ready["read_result"]
        assert (terminal_workspace / "live-result").read_bytes() == b"changed-after-read-canary"
    finally:
        (terminal_workspace / "live-result").write_bytes(original_read_source)
    terminal_report["typed_core_read_native_pam_checkpoint_and_custody"] = True
    terminal_report["typed_core_read_replay_no_execution_or_model_disclosure"] = True
    output_managed = managed | dict(context=managed["context"] | dict(
        operation_key="ci-terminal-output-core-witness"))
    output_plan = dict(args=dict(argv=["/usr/bin/python3", "-c",
        "import sys;from pathlib import Path;"
        "Path('/workspace/output-once').open('x').write('once');"
        "sys.stdout.buffer.write(bytes([0,255])*3500);"
        "sys.stderr.buffer.write(b'failure\\n'*1000);sys.exit(7)"], cwd=".", timeout_seconds=5),
        reason="Capture actual failed-command binary stdout and stderr")

    def output_step():
        result = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.lifecycle", "--mock"],
            input=json.dumps(dict(managed=output_managed, plan=output_plan)),
            capture_output=True, text=True, timeout=15, check=False)
        assert result.returncode == 0, result.stderr[-4096:]
        decoded = json.loads(result.stdout)
        assert decoded["ok"], decoded
        return decoded["task"]

    output_pending = output_step()
    assert output_pending["status"] == "awaiting_grant"
    output_view = human(dict(mode="view", id=output_pending["approval_id"]))["view"]
    assert human(dict(mode="confirm", view=output_view, password=password))["ok"]
    output_ready = output_step()
    deadline = time.monotonic() + 30
    while output_ready["status"] in {"queued", "running"} and time.monotonic() < deadline:
        output_ready = output_step()
    assert output_ready["status"] == "failed" and output_ready["terminal_output"] is not None
    assert output_ready["terminal_output"]["return_code"] == 7
    assert output_ready["terminal_output"]["effect_verified"] is False
    output_body = dict(task_id=terminal_task["task_id"], action_id=output_ready["action_id"])
    output_query = dict(schema_version="1.0", operation="terminal_output", body=output_body)
    assert rpc("request", output_query) == denied
    for change in (dict(task_id="0" * 32), dict(action_id="0" * 32)):
        assert rpc("request", output_query | dict(body=output_body | change),
                   actor=identity.name) == denied
    output_code = """import json,sys,hashlib
from mano_core.broker import BrokerClient,read_terminal_output
client=BrokerClient()
try:
 result=read_terminal_output(client,**json.load(sys.stdin))
 assert result['stdout']==bytes([0,255])*3500
 assert result['stderr']==b'failure\\n'*1000
 assert result['metadata']['return_code']==7
 print(json.dumps(dict(native_binary_stdout_stderr=True,output=result['metadata'])))
finally:client.close()
"""
    output_client = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "python3", "-c", output_code],
        input=json.dumps(output_body), capture_output=True, text=True, timeout=15, check=True)
    assert json.loads(output_client.stdout)["output"] == output_ready["terminal_output"]
    (terminal_workspace / "output-once").write_text("replay-canary")
    output_replay = output_step()
    assert output_replay["action_id"] == output_ready["action_id"]
    assert output_replay["terminal_output"] == output_ready["terminal_output"]
    assert (terminal_workspace / "output-once").read_text() == "replay-canary"
    terminal_report["native_terminal_output_failed_binary_multichunk_and_replay"] = True
    terminal_report["terminal_output_native_caller_task_scope"] = True
    terminal_report["terminal_output_witness"] = json.loads(output_client.stdout)
    # A broker-owned recorded workflow drives real core checkpoints and effects.
    # It may correct only the expected observed failure; no provider sees output.
    def developer_request(body):
        result = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "mano_broker.developer", "--recorded"],
            input=json.dumps(body), text=True, capture_output=True, timeout=15, check=False)
        assert result.returncode == 0, (result.stdout, result.stderr)
        decoded = json.loads(result.stdout)
        assert decoded["ok"], decoded
        return decoded["workflow"]

    def observed_test(plan, code, stdout=b"", stderr=b""):
        return dict(plan=plan, expect=dict(exit_code=code,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest()))

    broken_source = "def answer():\n    return 0\n"
    fixed_source = "def answer():\n    return 42\n"
    test_program = ("import sys;from workflow_answer import answer;value=answer();"
        "sys.stderr.write('FAIL expected 42 got 0\\n') if value!=42 else print('PASS');"
        "sys.exit(1 if value!=42 else 0)")
    test_plan = dict(capability="terminal.run", args=dict(argv=["/usr/bin/python3", "-c",
        test_program], cwd=".", timeout_seconds=5), reason="Run the recorded developer test")
    recorded_workflow = dict(steps=[
        dict(plan=dict(capability="files.write", args=dict(path="workflow_answer.py",
            text=broken_source), reason="Create the recorded initial project"), expect={}),
        observed_test(test_plan, 1, stderr=b"FAIL expected 42 got 0\n"),
        dict(plan=dict(capability="files.write", args=dict(path="workflow_answer.py",
            text=fixed_source), reason="Apply the recorded correction after the expected failure"),
            expect={}),
        observed_test(test_plan, 0, stdout=b"PASS\n")],
        artifact=dict(path="workflow_answer.py",
                      sha256=hashlib.sha256(fixed_source.encode()).hexdigest(),
                      size=len(fixed_source.encode())))
    registered_workflow = developer_request(dict(managed=managed,
        request_key="recorded-developer-project", workflow=recorded_workflow))
    workflow_id = registered_workflow["id"]
    assert registered_workflow["status"] == "ready"
    assert not (terminal_workspace / "workflow_answer.py").exists()
    assert rpc("request", dict(schema_version="1.0", operation="developer_workflow_status",
        body=dict(workflow_id=workflow_id)), actor=identity.name) == denied
    seen_approvals = set()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        workflow_state = developer_request(dict(workflow_id=workflow_id))
        if workflow_state["status"] == "verified":
            break
        assert workflow_state["status"] in {"ready", "awaiting_grant", "queued", "running",
                                             "needs_verification"}, workflow_state["status"]
        if workflow_state["status"] == "awaiting_grant":
            approval_id = workflow_state["approval_id"]
            assert approval_id not in seen_approvals
            seen_approvals.add(approval_id)
            workflow_view = human(dict(mode="view", id=approval_id))["view"]
            assert workflow_view["task_id"] == terminal_task["task_id"]
            assert human(dict(mode="confirm", view=workflow_view, password=password))["ok"]
        time.sleep(0.15)
    assert workflow_state["status"] == "verified", workflow_state["status"]
    assert len(seen_approvals) == 4 and len(workflow_state["observations"]) == 4
    assert workflow_state["observations"][1]["output"]["return_code"] == 1
    assert workflow_state["observations"][3]["output"]["return_code"] == 0
    assert workflow_state["provider_disclosure"] is False
    assert (terminal_workspace / "workflow_answer.py").read_text() == fixed_source
    witness = {key: workflow_state[key] for key in ("id", "status", "observations", "artifact_id",
               "verification_scope", "provider_disclosure")}
    (terminal_workspace / "workflow_answer.py").write_text("workflow replay canary")
    workflow_replay = developer_request(dict(workflow_id=workflow_id))
    assert workflow_replay["status"] == "verified"
    assert workflow_replay["observations"] == workflow_state["observations"]
    assert (terminal_workspace / "workflow_answer.py").read_text() == "workflow replay canary"
    witness.update(replay_no_effect=True, current_file_reverified=False, native_pam_approvals=4)
    terminal_report["recorded_developer_workflow_witness"] = witness
    terminal_report["recorded_developer_create_fail_fix_pass_exact_artifact"] = True
    terminal_report["recorded_developer_checkpoint_replay_no_model_disclosure"] = True
    # Explicitly selected historical failure; no automatic provider disclosure.
    feedback_source = workflow_state["observations"][1]["action_id"]
    feedback_managed = managed | dict(context=managed["context"] | dict(
        operation_key="approved-failure-feedback"))
    feedback_client = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os",
        "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", "-m", "mano_broker.lifecycle",
        "--broker-model"], input=json.dumps(dict(managed=feedback_managed,
        model=dict(model="explicit-snapshot", max_output_tokens=100,
                   feedback_action_id=feedback_source))),
        capture_output=True, text=True, timeout=20, check=False)
    assert feedback_client.returncode == 0, (feedback_client.stdout, feedback_client.stderr)
    feedback_task = json.loads(feedback_client.stdout)["task"]
    assert feedback_task["status"] == "awaiting_model_grant"
    from mano_protocol.actions import canonical as feedback_canonical

    feedback_key = "model-" + hashlib.sha256(feedback_canonical(dict(
        task_id=terminal_task["task_id"], resource_id=terminal_task["resource_id"],
        operation_key="approved-failure-feedback")).encode()).hexdigest()
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        feedback_pending = database.execute('SELECT id,proposal_json,state FROM approvals '
            'WHERE task_id=? AND request_key=?',
            (terminal_task["task_id"], feedback_key)).fetchone()
        assert feedback_pending[2] == "pending"
        assert database.execute('SELECT count(*) FROM provider_jobs').fetchone() == (0,)
        assert database.execute('SELECT count(*) FROM model_attempts').fetchone() == (0,)
    feedback_proposal = json.loads(feedback_pending[1])
    del feedback_proposal["grant_id"]
    feedback_value = feedback_proposal["args"]["feedback"]
    assert feedback_value["action_id"] == feedback_source
    assert feedback_value["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert feedback_value["return_code"] == 1 and feedback_value["untrusted"] is True
    assert feedback_value["stdout"]["text"] == ""
    assert feedback_value["stderr"]["text"] == "FAIL expected 42 got 0\n"
    assert feedback_value["stderr"]["sha256"] == hashlib.sha256(
        b"FAIL expected 42 got 0\n").hexdigest()
    feedback_view = human(dict(mode="view", id=feedback_pending[0]))["view"]
    assert feedback_view["args"] == feedback_proposal["args"]
    assert human(dict(mode="confirm", view=feedback_view, password="wrong-ci-password")) == {
        "ok": False}
    feedback_grant = human(dict(mode="confirm", view=feedback_view, password=password))
    assert feedback_grant["ok"]
    assert human(dict(mode="confirm", view=feedback_view, password=password)) == {"ok": False}
    forged_feedback = json.loads(json.dumps(feedback_proposal))
    forged_feedback["idempotency_key"] = "forged-feedback-other-action"
    forged_feedback["args"]["feedback"]["action_id"] = "f" * 32
    assert rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=forged_feedback), actor=identity.name) == denied
    # Existing disabled/mismatched provider policy must still deny dispatch after PAM.
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=feedback_proposal | dict(grant_id=feedback_grant["grant_id"])),
        actor=identity.name) == denied
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute('SELECT used FROM grants WHERE id=?',
                                (feedback_grant["grant_id"],)).fetchone() == (0,)
        assert database.execute('SELECT count(*) FROM provider_jobs').fetchone() == (0,)
        assert database.execute('SELECT count(*) FROM model_attempts').fetchone() == (0,)
    from mano_protocol.provider import request_body as feedback_request_body

    feedback_payload = feedback_request_body(feedback_proposal["args"]["prompt"],
        model="explicit-snapshot", max_output_tokens=100, feedback=feedback_value)
    assert len(feedback_payload["input"]) == 3
    assert feedback_payload["input"][2]["role"] == "user"
    assert "UNTRUSTED_EXECUTION_FEEDBACK_JSON" in feedback_payload["input"][2]["content"]
    assert feedback_source not in feedback_payload["input"][2]["content"]
    assert (terminal_workspace / "workflow_answer.py").read_text() == "workflow replay canary"
    terminal_report["approved_failure_feedback_witness"] = dict(
        feedback=feedback_value, request_key=feedback_key, native_pam=True,
        default_disclosure_disabled=True, forged_source_denied=True,
        provider_policy_still_denied=True, provider_jobs=0, model_attempts=0,
        source_reexecution=False, effect_verified=False, live_provider_request=False,
        prepared_payload_sha256=hashlib.sha256(json.dumps(
            feedback_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    terminal_report["approved_failure_feedback_native_pam_exact_custody"] = True
    terminal_report["approved_failure_feedback_no_implicit_provider_or_reexecution"] = True
    write_receipts = []
    for index, content in enumerate(("approved direct write \u2603", "")):
        direct_proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
            resource_id=terminal_task["resource_id"], capability="files.write",
            args=dict(path="direct-note", text=content),
            idempotency_key="direct-write-" + str(index),
            reason="Approve bounded direct workspace publication")
        direct_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
            body=direct_proposal), actor=identity.name)["approval"]
        assert direct_pending["state"] == "pending"
        if index == 0:
            assert not (terminal_workspace / "direct-note").exists()
        direct_view = human(dict(mode="view", id=direct_pending["approval_id"]))["view"]
        assert direct_view["args"] == direct_proposal["args"]
        assert human(dict(mode="confirm", view=direct_view,
                          password="wrong-ci-password")) == {"ok": False}
        direct_grant = human(dict(mode="confirm", view=direct_view, password=password))
        assert direct_grant["ok"]
        direct_request = dict(schema_version="1.0", operation="propose",
            body=direct_proposal | dict(grant_id=direct_grant["grant_id"]))
        direct_action = rpc("request", direct_request, actor=identity.name)["action"]["id"]
        direct_query = dict(schema_version="1.0", operation="file_write_result", body=dict(
            task_id=terminal_task["task_id"], action_id=direct_action))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            direct_result = rpc("request", direct_query, actor=identity.name)
            if direct_result["ok"] and direct_result["publication"] is not None:
                break
            time.sleep(0.15)
        receipt = direct_result["publication"]
        assert receipt is not None, direct_result
        assert receipt["sha256"] == hashlib.sha256(content.encode()).hexdigest()
        assert receipt["size"] == len(content.encode())
        assert receipt["publication"] == ("created" if index == 0 else "replace-slot")
        assert receipt["effect_verified"] is False and receipt["current_content_verified"] is False
        assert (terminal_workspace / "direct-note").read_text() == content
        task_read = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--",
            "/bin/cat", str(terminal_workspace / "direct-note")], capture_output=True, check=True)
        assert task_read.stdout == content.encode()
        assert rpc("request", direct_query) == denied
        for change in (dict(task_id="0" * 32), dict(action_id="0" * 32)):
            assert rpc("request", direct_query | dict(body=direct_query["body"] | change),
                       actor=identity.name) == denied
        receipt_code = """import json,sys
from mano_core.broker import BrokerClient,file_write_result
client=BrokerClient()
try:print(json.dumps(file_write_result(client,**json.load(sys.stdin))))
finally:client.close()
"""
        receipt_client = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--", "env",
            "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", receipt_code],
            input=json.dumps(direct_query["body"] | dict(path="direct-note")),
            text=True, capture_output=True, check=True, timeout=5)
        assert json.loads(receipt_client.stdout) == receipt
        (terminal_workspace / "direct-note").write_text("later canary")
        direct_replay = rpc("request", direct_request, actor=identity.name)
        assert not direct_replay["fresh"] and direct_replay["action"]["state"] == "done"
        assert (terminal_workspace / "direct-note").read_text() == "later canary"
        assert rpc("request", direct_query, actor=identity.name) == direct_result
        write_receipts.append(receipt)
    terminal_report["direct_workspace_write_native_pam_create_replace_empty_sdk"] = True
    terminal_report["direct_workspace_write_scope_and_no_reexecution"] = True
    terminal_report["direct_workspace_write_receipts"] = write_receipts
    # Public PTY creation requires its own exact native PAM approval; active
    # permission profiles deliberately do not grant interactive channels.
    public_pty_program = r"""import os,sys,ctypes
from pathlib import Path
assert all(os.isatty(fd) for fd in (0,1,2))
libc=ctypes.CDLL(None,use_errno=True);libc.tcgetsid.argtypes=[ctypes.c_int]
libc.tcgetsid.restype=ctypes.c_int
assert libc.tcgetsid(0)==os.getsid(0)
assert os.tcgetpgrp(0)==os.getpgrp()
assert os.environ['TERM']=='xterm-256color'
assert not any(k in os.environ for k in ('DISPLAY','WAYLAND_DISPLAY','DBUS_SESSION_BUS_ADDRESS'))
Path('/workspace/public-pty-started').write_text('started')
print('READY',flush=True)
count=0
for line in sys.stdin:
 if line=='size\n':
  size=os.get_terminal_size(0);print('SIZE:%d:%d'%(size.lines,size.columns),flush=True)
 else:
  count+=1;print('LINE:'+line.strip(),flush=True)
print('END:%d'%count,flush=True)
"""
    public_pty_proposal = dict(schema_version="1.0", task_id=terminal_task["task_id"],
        resource_id=terminal_task["resource_id"], capability="terminal.open_pty",
        args=dict(argv=["/usr/bin/python3", "-c", public_pty_program], cwd=".",
                  timeout_seconds=30, rows=24, columns=80, input_limit_bytes=128),
        idempotency_key="public-pty-open", reason="Approve bounded interactive task PTY")
    public_pty_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=public_pty_proposal), actor=identity.name)["approval"]
    assert public_pty_pending["state"] == "pending"
    assert not (terminal_workspace / "public-pty-started").exists()
    public_pty_view = human(dict(mode="view", id=public_pty_pending["approval_id"]))["view"]
    assert public_pty_view["args"] == public_pty_proposal["args"]
    assert human(dict(mode="confirm", view=public_pty_view,
                      password="wrong-ci-password")) == {"ok": False}
    assert not (terminal_workspace / "public-pty-started").exists()
    public_pty_grant = human(dict(mode="confirm", view=public_pty_view, password=password))
    assert public_pty_grant["ok"]
    public_pty_open = dict(schema_version="1.0", operation="propose",
        body=public_pty_proposal | dict(grant_id=public_pty_grant["grant_id"]))
    public_pty_action = rpc("request", public_pty_open, actor=identity.name)["action"]["id"]
    public_pty_body = dict(task_id=terminal_task["task_id"], action_id=public_pty_action)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not (terminal_workspace / "public-pty-started").exists():
        time.sleep(0.1)
    assert (terminal_workspace / "public-pty-started").read_text() == "started"
    public_pty_query = dict(schema_version="1.0", operation="pty_status", body=public_pty_body)
    assert rpc("request", public_pty_query) == denied
    for change in (dict(task_id="0"*32), dict(action_id="0"*32)):
        assert rpc("request", public_pty_query | dict(body=public_pty_body | change),
                   actor=identity.name) == denied
    public_pty_client = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "python3",
        str(ROOT / "scripts/probe_public_pty_client.py")], input=json.dumps(dict(
            proposal=public_pty_proposal, grant_id=public_pty_grant["grant_id"],
            action_id=public_pty_action)),
        capture_output=True, text=True, timeout=25, check=False)
    assert public_pty_client.returncode == 0, (public_pty_client.stdout, public_pty_client.stderr)
    terminal_report["public_broker_pty_witness"] = json.loads(public_pty_client.stdout)
    assert rpc("request", public_pty_open, actor=identity.name)["fresh"] is False
    terminal_report["public_broker_pty_pam_sdk_replay_geometry_eof"] = True
    terminal_report["public_broker_pty_native_caller_scope"] = True
    pty_unit = "mano-pty-probe-" + secrets.token_hex(6)
    authorization = os.open(terminal_workspace / ".pty-ci-authorized",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    with os.fdopen(authorization, "wb") as stream:
        os.fchmod(stream.fileno(), 0o640)
        os.fchown(stream.fileno(), 0, identity.gid)
        stream.write(b"mano-phase0-ci-task-pty\n")
    pty_units.extend([pty_unit + ".service", pty_unit + "-frozen.service"])
    pty_base = ["systemd-run", "--quiet", "--pipe", "--collect", "--uid=" + identity.name,
        "--slice=mano-core.slice", "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
        "--property=MemoryMax=128M", "--property=TasksMax=24", "--property=CPUQuota=30%",
        "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=1",
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
        "--property=ReadWritePaths=" + str(terminal_workspace),
        "--property=PrivateTmp=yes"]
    pty_program = ["env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8",
        "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3",
        str(ROOT / "scripts/probe_task_pty.py"), str(terminal_workspace)]
    pty_probe = subprocess.run(pty_base + ["--unit=" + pty_unit, "--wait"] + pty_program,
        capture_output=True, text=True, timeout=45, check=False)
    assert pty_probe.returncode == 0, (pty_probe.stdout[-2048:], pty_probe.stderr[-4096:])
    pty_report = json.loads(pty_probe.stdout)
    assert pty_report["task_owned_controlling_pty"] is True
    assert pty_report["public_broker_session_implemented"] is False
    # Root creates a synthetic foreign-owned PTY, never the user's actual terminal.
    foreign_master, foreign_slave = os.openpty()
    try:
        foreign = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--",
            "/usr/bin/setpriv", "--no-new-privs"] +
            pty_program + ["--foreign"], stdin=foreign_slave, stdout=foreign_slave,
            stderr=foreign_slave, timeout=15, check=False)
        assert foreign.returncode == 125, foreign.returncode
        os.set_blocking(foreign_master, False)
        foreign_output = bytearray()
        while True:
            try:
                piece = os.read(foreign_master, 4096)
            except BlockingIOError:
                break
            if not piece:
                break
            foreign_output.extend(piece)
        assert b"guard task-owned PTY" in foreign_output, bytes(foreign_output)
    finally:
        os.close(foreign_slave)
        os.close(foreign_master)
    pty_report["foreign_uid_slave_denied"] = True
    terminal_report["task_owned_pty_worker_kernel_contract"] = pty_report
    terminal_report["task_owned_pty_interactive_guard_contract"] = True
    terminal_report["real_coding_delegate_contracts"] = delegate_contracts
    terminal_report["real_coding_delegate_versions_help_sealed_home_and_config_consumption"] = (
        delegate_probe_passed)
    from mano_core.delegates import proposal as delegate_proposal
    from mano_protocol.delegates import VERSIONS as delegate_versions

    delegate_sdk_results = {}
    for delegate_name, delegate_version in delegate_versions.items():
        proposed_delegate = delegate_proposal(delegate=delegate_name, operation="version",
            task_id=terminal_task["task_id"], resource_id=terminal_task["resource_id"],
            key="actual-sdk-delegate-" + delegate_name, reason="Inspect actual pinned coding CLI",
            timeout_seconds=20)
        delegate_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
            body=proposed_delegate), actor=identity.name)["approval"]
        assert delegate_pending["state"] == "pending"
        delegate_view = human(dict(mode="view", id=delegate_pending["approval_id"]))["view"]
        delegate_grant = human(dict(mode="confirm", view=delegate_view, password=password))
        assert delegate_grant["ok"]
        delegate_client_code = """import json,sys,time
from mano_core.broker import BrokerClient
from mano_core.delegates import CodingDelegate
value=json.load(sys.stdin);client=BrokerClient()
try:
 worker=CodingDelegate.open(client,proposal=value['proposal'],grant_id=value['grant_id'])
 deadline=time.monotonic()+25;count=0
 while time.monotonic()<deadline:
  data=worker.read();count+=len(data['events'])
  if data['eof']:break
 assert data['eof']
 result=worker.result();assert result['status']=='inspection'
 assert result['effect_verified'] is False and result['events_untrusted'] is True
 print(json.dumps(dict(result=result,event_count=count,action_id=worker.session.action_id)))
finally:client.close()
"""
        delegate_client = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--", "env",
            "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "python3", "-c",
            delegate_client_code], input=json.dumps(dict(proposal=proposed_delegate,
            grant_id=delegate_grant["grant_id"])), text=True, capture_output=True,
            timeout=35, check=False)
        assert delegate_client.returncode == 0, (delegate_client.stdout, delegate_client.stderr)
        delegate_sdk_results[delegate_name] = json.loads(delegate_client.stdout)
        assert delegate_sdk_results[delegate_name]["result"]["version"] == delegate_version
    terminal_report["real_coding_delegate_native_pam_public_sdk"] = True
    terminal_report["real_coding_delegate_sdk_witness"] = delegate_sdk_results
    (ROOT / "evidence/coding-delegate-public-sdk.json").write_text(
        json.dumps(delegate_sdk_results, indent=2) + "\n")
    assert delegate_probe_passed, (delegate_probe.stdout[-4096:],
                                   delegate_probe.stderr[-8192:])
    from probe_mcp import run as probe_mcp

    mcp_records = probe_mcp(rpc, human, identity, password, terminal_task, terminal_workspace)
    terminal_report["mcp_discovery_official_sdk_native_pam_and_hostile_peers"] = True
    terminal_report["mcp_discovery_witness"] = mcp_records
    (ROOT / "evidence/mcp-discovery.json").write_text(json.dumps(mcp_records, indent=2) + "\n")
    _, exhausted = profiled_request("files.read", dict(path="live-result"))
    assert exhausted["state"] == "pending" and exhausted["grant_id"] is None
    _, supervised_write = profiled_request("files.write", dict(path="no-write", text="denied"))
    assert supervised_write["state"] == "pending"
    mode_prompt = human_receipt["prompt"]["id"]
    mode_key = secrets.token_hex(16)
    mode_args = (mode_prompt, "auto", "--duration", "60", "--max-actions", "2",
                 "--request-key", mode_key)
    cancel_code, cancel_output = native_terminal('mano_prompt.mode', mode_args,
        actor='mano-human', answers=((b'Approve this exact operation?', 'n'),))
    assert cancel_code == 0 and b'Cancelled. No profile was activated.' in cancel_output
    assert human(dict(mode="permission_status", id=mode_prompt))["profile"]["automatic"] is False
    wrong_code, wrong_output = native_terminal('mano_prompt.mode', mode_args,
        actor='mano-human', answers=((b'Approve this exact operation?', 'y'),
                                    (b'OS authentication password:', 'wrong-ci-password')))
    assert wrong_code == 1 and b'wrong-ci-password' not in wrong_output
    assert human(dict(mode="permission_status", id=mode_prompt))["profile"]["automatic"] is False
    mode_code, mode_output = native_terminal('mano_prompt.mode', mode_args,
        actor='mano-human', answers=((b'Approve this exact operation?', 'y'),
                                    (b'OS authentication password:', password)))
    assert mode_code == 0 and b'Approval recorded:' in mode_output
    assert password.encode() not in mode_output
    current_permission = human(dict(mode="permission_status", id=mode_prompt))["profile"]
    assert current_permission["automatic"] is True and current_permission["mode"] == "auto"
    assert current_permission["remaining_actions"] == 2
    status_code, status_output = native_terminal('mano_prompt.mode', (mode_prompt, '--status'),
                                                actor='mano-human')
    assert status_code == 0 and b'"automatic": true' in status_output
    for actor in ("mano-agent", "mano-core", "mano-worker", identity.name):
        assert human(dict(mode="permission_status", id=mode_prompt), actor=actor) == {"ok": False}
    from mano_prompt.mode import profile_packet

    wire = profile_packet(mode_prompt, secrets.token_hex(16), dict(mode='auto',
        duration_seconds=60, max_actions=2, max_timeout_seconds=10))
    for malformed in (wire[:-1], wire+b'extra', wire[:66]+b'\x03'+wire[67:]):
        assert human(dict(mode="raw_prompt", wire=malformed.hex())) == {"ok": False}
    terminal_report["human_mode_tty_cancel_wrong_password_retry_and_status"] = True
    from probe_live_human import run as live_human_permissions

    live_gui = live_human_permissions(native_terminal, password, extra_gui_identities.append, human)
    assert live_gui['effective']['status']['automatic'] is True
    terminal_report["production_gui_native_broker_tty_pam_profile_refresh"] = True
    _, unlisted = profiled_request("terminal.run", dict(argv=["/bin/sh", "-c", "true"],
                                                       cwd=".", timeout_seconds=2))
    assert unlisted["state"] == "pending"
    auto_program = ("from pathlib import Path;"
                    "Path('/workspace/profile-auto-ok').write_text('auto-ok')")
    for mode, argv, filename, expected in (
        ("auto", ["/usr/bin/python3", "-c", auto_program], "profile-auto-ok", "auto-ok"),
        ("full-access", ["/bin/sh", "-c", "if touch /etc/mano/profile-bypass 2>/dev/null; "
            "then exit 99; fi; test ! -e /var/lib/mano-broker/runtime/state.sqlite3 && "
            "printf full-ok > /workspace/profile-full-ok"], "profile-full-ok", "full-ok"),
    ):
        if mode == "full-access":
            install_profile(mode, operator_password=password)
        proposal, approved = profiled_request("terminal.run", dict(argv=argv, cwd=".",
                                                                  timeout_seconds=5))
        assert approved["state"] == "approved" and approved["grant_id"]
        body = proposal | dict(grant_id=approved["grant_id"])
        assert rpc("request", dict(schema_version="1.0", operation="propose",
            body=body | dict(args=body["args"] | dict(timeout_seconds=6))),
            actor=identity.name) == denied
        submitted = rpc("request", dict(schema_version="1.0", operation="propose", body=body),
                        actor=identity.name)
        assert submitted["ok"]
        query = dict(schema_version="1.0", operation="status", body=dict(
            task_id=terminal_task["task_id"], action_id=submitted["action"]["id"]))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = rpc("request", query, actor=identity.name)["action"]
            if status["state"] in {"done", "failed", "unknown"}:
                break
            time.sleep(0.1)
        assert status["state"] == "done", status
        assert (terminal_workspace / filename).read_text() == expected
    assert not Path("/etc/mano/profile-bypass").exists()
    _, model_outside_scope = profiled_request("model.plan", cloud_proposal["args"])
    assert model_outside_scope["state"] == "pending"
    install_profile("auto", operator_password=password, count=1, duration=3)
    expired_proposal, expired_grant = profiled_request("files.read", dict(path="live-result"))
    assert expired_grant["state"] == "approved"
    time.sleep(3.1)  # Actual lease expiry, not a mocked trusted clock.
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=expired_proposal | dict(grant_id=expired_grant["grant_id"])),
        actor=identity.name) == denied
    install_profile("supervised", operator_password=password, count=2, duration=900)
    profile_stop_proposal, profile_stop_grant = profiled_request(
        "files.read", dict(path="live-result"))
    assert profile_stop_grant["state"] == "approved"
    terminal_report["permission_profiles_native_pam_count_expiry_and_exact_grants"] = True
    terminal_report["full_workspace_profile_protected_policy_kernel_denial"] = True

    stop_proposal = terminal_proposal | dict(idempotency_key="native-stop-task", args=dict(
        argv=["/usr/bin/python3", "-c", "import os,time;from pathlib import Path;"
              "p=os.fork()\nif p==0:\n os.setsid()\n"
              " Path('/workspace/stoppable.pending').write_text('ready');"
              "os.replace('/workspace/stoppable.pending','/workspace/stoppable')\ntime.sleep(60)"],
        cwd=".", timeout_seconds=60))
    stop_workflow_definition = dict(steps=[observed_test(dict(capability="terminal.run",
        args=stop_proposal["args"], reason="Recorded long-running test for native Stop"), 0),
        dict(plan=dict(capability="files.write", args=dict(path="workflow-stop-must-not-write",
            text="must never run"), reason="Forbidden continuation after unknown effect"),
            expect={}),
        observed_test(dict(capability="terminal.run", args=dict(argv=["/usr/bin/true"], cwd=".",
            timeout_seconds=1), reason="Unreachable final step"), 0)],
        artifact=dict(path="workflow-stop-must-not-write", sha256=hashlib.sha256(b"").hexdigest(),
                      size=0))
    stop_workflow = developer_request(dict(managed=managed, request_key="recorded-stop-workflow",
                                            workflow=stop_workflow_definition))
    stop_workflow = developer_request(dict(workflow_id=stop_workflow["id"]))
    assert stop_workflow["status"] == "awaiting_grant"
    stop_view = human(dict(mode="view", id=stop_workflow["approval_id"]))["view"]
    assert human(dict(mode="confirm", view=stop_view, password=password))["ok"]
    stop_workflow = developer_request(dict(workflow_id=stop_workflow["id"]))
    assert stop_workflow["status"] in {"queued", "running"}
    stop_action = dict(action=dict(id=stop_workflow["action_id"]))
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
    for actor, arguments in (("mano-human", ["--socket", "/tmp/forged"]),
                             (identity.name, [])):
        rejected = subprocess.run(["/usr/sbin/runuser", "-u", actor, "--", str(STOP_CLIENT),
                                   *arguments], capture_output=True, text=True, timeout=5)
        assert rejected.returncode != 0 and not rejected.stdout
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
    core_unit = "mano-core-frozen-ci.service"
    subprocess.run(["systemd-run", "--quiet", "--collect", "--unit=" + core_unit,
        "--uid=" + identity.name, "--slice=mano-core.slice", "--property=MemoryMax=256M",
        "--property=TasksMax=32", "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
        "--property=TimeoutStopSec=1", "--property=RuntimeMaxSec=60",
        "--property=ProtectHome=yes", "--property=ProtectSystem=strict",
        "/usr/bin/python3", "-c", "import os,time;child=os.fork();"
        "os.setsid() if child==0 else None;time.sleep(60)"], check=True,
        capture_output=True, text=True, timeout=5)
    core_group = Path("/sys/fs/cgroup/mano.slice/mano-core.slice")
    core_child_group = core_group / core_unit
    deadline = time.monotonic() + 3
    stop_pty_proposal = public_pty_proposal | dict(idempotency_key="public-pty-stop",
        args=public_pty_proposal["args"] | dict(timeout_seconds=60, argv=["/usr/bin/python3", "-c",
            "from pathlib import Path;import time;"
            "Path('/workspace/public-pty-stop').write_text('ready');time.sleep(60)"]))
    stop_pty_pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
        body=stop_pty_proposal), actor=identity.name)["approval"]
    assert stop_pty_pending["state"] == "pending"
    stop_pty_view = human(dict(mode="view", id=stop_pty_pending["approval_id"]))["view"]
    stop_pty_grant = human(dict(mode="confirm", view=stop_pty_view, password=password))
    assert stop_pty_grant["ok"]
    stop_pty_action = rpc("request", dict(schema_version="1.0", operation="propose",
        body=stop_pty_proposal | dict(grant_id=stop_pty_grant["grant_id"])),
        actor=identity.name)["action"]["id"]
    stop_pty_group = Path("/sys/fs/cgroup/system.slice/mano-launcher.service") / (
        "task-" + stop_pty_action)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not (terminal_workspace / "public-pty-stop").exists():
        time.sleep(0.1)
    assert (terminal_workspace / "public-pty-stop").read_text() == "ready"
    stop_pty_pids = [int(pid) for pid in (stop_pty_group / "cgroup.procs").read_text().split()]
    assert len(stop_pty_pids) >= 3
    stop_pty_write = dict(schema_version="1.0", operation="pty_write", body=dict(
        task_id=terminal_task["task_id"], action_id=stop_pty_action, key="after-stop",
        data=base64.b64encode(b"must-not-arrive\n").decode()))
    from probe_mcp import start_for_stop as start_mcp_for_stop

    mcp_stop = start_mcp_for_stop(rpc, human, identity, password, terminal_task)
    terminal_report["mcp_frozen_stop_witness"] = mcp_stop
    core_pids = []
    pty_frozen = subprocess.Popen(pty_base + ["--unit=" + pty_unit + "-frozen", "--wait"] +
        pty_program + ["--freeze"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 15
    while not (terminal_workspace / "pty-fixture-ready").exists() and time.monotonic() < deadline:
        assert pty_frozen.poll() is None
        time.sleep(0.05)
    assert (terminal_workspace / "pty-fixture-ready").exists()
    pty_worker_pid = int(command("systemctl", "show", pty_unit + "-frozen.service",
                                 "--property=MainPID", "--value"))
    pty_child_pid = int((terminal_workspace / "pty-fixture-ready").read_text())
    assert pty_worker_pid > 0 and pty_child_pid > 0
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        core_pids = [int(pid) for pid in (core_child_group / "cgroup.procs").read_text().split()]
        if len(core_pids) == 2:
            break
        time.sleep(0.05)
    assert len(core_pids) == 2
    core_pids.extend([pty_worker_pid, pty_child_pid])
    core_pids.extend(stop_pty_pids)
    core_pids.extend(mcp_stop["pids"])
    provider_idle, _provider_unit, provider_pids = provider_idle_job()
    provider_stop_probe = """import json
from mano_protocol.stop_state import snapshot
state=snapshot()
print(json.dumps(dict(generation=state.generation,latched=state.latched)))
"""
    observed = subprocess.run(["/usr/bin/nsenter", "--target", str(provider_pids[0]),
        "--mount", "--", "/usr/sbin/runuser", "-u", "mano-provider", "--", "env",
        "PYTHONPATH=/usr/lib/mano-os", "python3", "-c", provider_stop_probe],
        capture_output=True, text=True, check=True, timeout=10)
    from mano_protocol.stop_state import snapshot as root_stop_snapshot

    root_snapshot = root_stop_snapshot()
    assert not root_snapshot.latched
    assert json.loads(observed.stdout) == dict(generation=root_snapshot.generation, latched=False)
    terminal_report["installed_provider_native_stop_snapshot"] = True
    core_pids.extend(provider_pids)
    profile_stop_proposal, profile_stop_grant = profiled_request(
        "files.read", dict(path="live-result"))
    assert profile_stop_grant["state"] == "approved"
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        active_before_stop = database.execute('SELECT expires,revoked,used FROM grants WHERE id=?',
            (profile_stop_grant["grant_id"],)).fetchone()
        assert active_before_stop[0] > time.monotonic() and active_before_stop[1:] == (0, 0)
    subprocess.run(["kill", "-STOP", *(str(pid) for pid in core_pids)], check=True)
    subprocess.run(["kill", "-STOP", str(broker_pid), str(launcher_pid)], check=True)
    try:
        native_stopped = subprocess.run(["/usr/sbin/runuser", "-u", "mano-human", "--",
            str(STOP_CLIENT)], check=True, capture_output=True, text=True, timeout=5)
        assert "Emergency Stop acknowledged" in native_stopped.stdout
        deadline = time.monotonic() + 3
        while (time.monotonic() < deadline
               and "populated 1" in (group / "cgroup.events").read_text()):
            time.sleep(0.05)
        assert "populated 0" in (group / "cgroup.events").read_text()
        deadline = time.monotonic() + 3

        def core_exited(pid):
            try:
                state_line = next(line for line in Path(f"/proc/{pid}/status").read_text()
                                  .splitlines() if line.startswith("State:"))
                return "Z" in state_line
            except (FileNotFoundError, ProcessLookupError):
                return True

        while time.monotonic() < deadline:
            if ("populated 0" in (core_group / "cgroup.events").read_text()
                    and all(core_exited(pid) for pid in core_pids)):
                break
            time.sleep(0.05)
        assert "populated 0" in (core_group / "cgroup.events").read_text()
        assert all(core_exited(pid) for pid in core_pids)
        assert (STOP_STATE / "state").read_text() == "v1:1:latched\n"
        for frozen in (broker_pid, launcher_pid):
            assert "T" in next(line for line in Path(f"/proc/{frozen}/status").read_text()
                               .splitlines() if line.startswith("State:"))
    finally:
        subprocess.run(["kill", "-CONT", str(broker_pid), str(launcher_pid)], check=False)
        subprocess.run(["systemctl", "stop", core_unit], check=False, capture_output=True,
                       timeout=3)
        provider_idle.terminate()
        provider_idle.wait(timeout=3)
        pty_frozen.communicate(timeout=5)
    terminal_report["mcp_discovery_frozen_native_stop_detached_descendants_drained"] = True
    terminal_report["native_human_stop_client_frozen_core_and_authority"] = True
    terminal_report["native_stop_client_message"] = native_stopped.stdout.strip()
    terminal_report["native_stop_broker_and_launcher_frozen"] = True
    terminal_report["native_stop_frozen_core_and_detached_child_drained"] = True
    terminal_report["native_stop_frozen_provider_drained"] = True
    terminal_report["native_stop_frozen_task_pty_worker_and_child_drained"] = True
    assert not stop_pty_group.exists() or "populated 0" in (
        stop_pty_group / "cgroup.events").read_text()
    assert rpc("request", stop_pty_write, actor=identity.name) == denied
    terminal_report["public_broker_pty_frozen_native_stop_drained"] = True
    terminal_report["installed_broker_disabled_price_policy"] = True
    terminal_report["loaded_broker_price_policy_immutable_snapshot"] = True
    terminal_report["installed_provider_credential_health"] = True
    terminal_report["installed_provider_disabled_generation_denied"] = True
    terminal_report["provider_kernel_runtime_deadline_verified"] = True
    terminal_report["provider_frozen_job_deadline_seconds"] = provider_deadline_seconds
    terminal_report["native_stop_capabilities_zero"] = True
    terminal_report["native_stop_task_cgroup_drained"] = True
    terminal_report["native_stop_latch_written"] = True
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=profile_stop_proposal | dict(grant_id=profile_stop_grant["grant_id"])),
        actor=identity.name) == denied
    terminal_report["native_stop_revokes_permission_profile_authority"] = True
    query_stop = dict(schema_version="1.0", operation="status", body=dict(
        task_id=terminal_task["task_id"], action_id=stop_action["action"]["id"]))
    stopped_status = rpc("request", query_stop, actor=identity.name)["action"]
    assert stopped_status["state"] == "unknown" and stopped_status["verified"] == 0
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=terminal_body), actor=identity.name) == denied
    revoked = rpc("request", dict(schema_version="1.0", operation="approval_status",
        body=dict(approval_id=pending_revoke["approval_id"])), actor=identity.name)
    assert revoked["approval"]["state"] == "revoked"
    stopped_snapshot = human(task_snapshot_query)["snapshot"]
    assert any(item["action_id"] == stop_action["action"]["id"]
               and item["state"] == "unknown" and item["effect_verified"] is False
               for item in stopped_snapshot["actions"])
    assert any(item["approval_id"] == pending_revoke["approval_id"]
               and item["state"] == "revoked" for item in stopped_snapshot["approvals"])
    terminal_report["human_task_snapshot_stop_unknown_and_revoked"] = True
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
    assert rpc("request", dict(schema_version="1.0", operation="propose",
        body=profile_stop_proposal | dict(grant_id=profile_stop_grant["grant_id"])),
        actor=identity.name) == denied
    with contextlib.closing(sqlite3.connect(
            f"file:{STATE / 'state.sqlite3'}?mode=ro", uri=True)) as database:
        assert database.execute('SELECT revoked FROM grants WHERE id=?',
            (profile_stop_grant["grant_id"],)).fetchone() == (1,)
    terminal_report["live_profile_grant_stop_rearm_no_resurrection"] = True
    stopped_workflow = developer_request(dict(workflow_id=stop_workflow["id"]))
    assert stopped_workflow["status"] == "revoked"
    assert not (terminal_workspace / "workflow-stop-must-not-write").exists()
    terminal_report["recorded_developer_native_stop_restart_no_follow_on_effect"] = True
    assert rpc("request", stop_pty_write, actor=identity.name) == denied
    terminal_report["public_broker_pty_restart_stop_rearm_no_input_resurrection"] = True


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
    key_path = PROVIDER_SECRETS / "openai"
    preserved_key = PROVIDER_SECRETS / "openai-ci-preserved"
    assert not preserved_key.exists()
    original_key_bytes = key_path.read_bytes()  # Synthetic fixture only, never an operator key.
    native_code, native_output = native_key_setup()
    assert native_code == 1 and b'Provider API key:' not in native_output
    assert key_path.read_bytes() == original_key_bytes
    key_path.rename(preserved_key)
    fake_setup_key = "ci-native-terminal-provisioned-key"
    config_before_setup = {path: path.read_bytes() for path in (
        PROVIDER_POLICY, PRICING_POLICY, CONTROLLER_POLICY, EGRESS_POLICY)}
    try:
        rejected_pipe = subprocess.run(["env", "PYTHONPATH=/usr/lib/mano-os", "python3", "-m",
            "mano_broker.provider_setup"], input="not-a-terminal", capture_output=True,
            text=True, timeout=5, check=False)
        assert rejected_pipe.returncode == 1 and not key_path.exists()
        native_code, native_output = native_key_setup(fake_setup_key)
        assert native_code == 0 and b'"credential_installed":true' in native_output
        # No secret echo, even in fixture output.
        assert fake_setup_key.encode() not in native_output
        info = key_path.lstat()
        assert info.st_uid == 0 and info.st_gid == 0 and info.st_nlink == 1
        assert info.st_mode & 0o777 == 0o600
        assert key_path.read_bytes() == fake_setup_key.encode()
        assert set(path.name for path in PROVIDER_SECRETS.iterdir()) == {
            "openai", "openai-ci-preserved"}
        native_code, native_output = native_key_setup()
        assert native_code == 1 and b'Provider API key:' not in native_output
        assert key_path.read_bytes() == fake_setup_key.encode()
        assert all(path.read_bytes() == value for path, value in config_before_setup.items())
        assert (STOP_STATE / "state").read_text() == "v1:7:latched\n"
    finally:
        if key_path.exists():
            assert key_path.read_bytes() == fake_setup_key.encode()
            key_path.unlink()  # Only the known synthetic key created by this test.
        preserved_key.rename(key_path)
    terminal_report["native_root_tty_key_provisioning_no_echo"] = True
    terminal_report["key_setup_no_overwrite_no_activation_no_rearm"] = True
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
                native_library_broker_uid_target_fd_verified=True,
                target_pin_probe_scope="separate Root-supervised broker-UID native library probe",
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
            "-u",
            "mano-provider@*.service",
            "-u",
            "mano-controller.service",
            "-u",
            "mano-egress@*.service",
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
    provider_units = [line.split()[0] for line in command("systemctl", "list-units", "--all",
        "--plain", "--no-legend", "mano-provider@*.service",
        "mano-egress@*.service").splitlines() if line.strip()]
    if pty_units:
        subprocess.run(["systemctl", "stop", *pty_units], check=False,
                       capture_output=True, timeout=5)
    if pin_probe is not None:
        if pin_probe.poll() is None:
            pin_probe.kill()
            pin_probe.communicate(timeout=5)
        for stream in (pin_probe.stdin, pin_probe.stdout, pin_probe.stderr):
            stream.close()
    if pty_frozen is not None:
        if pty_frozen.returncode is None:
            pty_frozen.communicate(timeout=5)
        for stream in (pty_frozen.stdout, pty_frozen.stderr):
            if stream is not None:
                stream.close()
    if provider_units:
        subprocess.run(["systemctl", "stop", *provider_units], check=False, capture_output=True,
                       timeout=5)
    subprocess.run(["systemctl", "stop", *(unit for unit in UNITS if "@" not in unit)],
                   check=False, capture_output=True)
    subprocess.run(["usermod", "-L", "mano-human"], check=False, capture_output=True)
    for file in (LIBRARY, NATIVE, STOP_NATIVE, STOP_CLIENT, POLICY, PAM, GUARD, PROVIDER_POLICY,
                 PRICING_POLICY, CONTROLLER_POLICY, EGRESS_POLICY, *installed):
        file.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    subprocess.run(
        ["systemctl", "reset-failed", "mano-broker.service", "mano-approve.service"],
        check=False,
        capture_output=True,
    )
    for directory in (STATE, CODE, WORK, BASE, STOP_STATE, PROVIDER_SECRETS):
        if directory.exists():
            shutil.rmtree(directory)
    STATE.parent.chmod(old_mode)
    if identity is not None:
        subprocess.run(["userdel", identity.name], check=False, capture_output=True)
    for gui_identity in extra_gui_identities:
        subprocess.run(["userdel", gui_identity], check=False, capture_output=True)
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
    if created_egress_user:
        subprocess.run(["userdel", "mano-egress"], check=False, capture_output=True)
        subprocess.run(["groupdel", "mano-egress"], check=False, capture_output=True)
    if created_provider_user:
        subprocess.run(["userdel", "mano-provider"], check=False, capture_output=True)
        subprocess.run(["groupdel", "mano-provider"], check=False, capture_output=True)
    egress_dir = Path("/run/mano-egress")
    if egress_dir.exists():
        egress_dir.rmdir()
    provider_dir = Path("/run/mano-provider")
    if provider_dir.exists():
        provider_dir.rmdir()
    if created_group:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
