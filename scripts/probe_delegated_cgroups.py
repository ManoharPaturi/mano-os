#!/usr/bin/env python3
"""Real delegated service cgroup custody in the disposable VM, no task argv."""

import ctypes
import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mano_broker.cgroups import ROOT, Manager
from mano_broker.credentials import drop
from mano_broker.identities import LOCK, allocate_identity
from mano_broker.launch_admission import LaunchAdmission
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.sandbox import GUARD
from mano_broker.state import Denied
from mano_broker.supervisor import Child
from mano_broker.workspaces import BASE, create_workspace

STATE = Path("/run/mano-delegation-ci")
CODE = Path("/usr/lib/mano-os")
UNIT_FILE = Path("/etc/systemd/system/mano-launcher.service")
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}

if sys.argv[1:] == ["--inner"]:

    def security_state(stage):
        fields = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        )
        print(
            json.dumps(
                dict(
                    stage=stage,
                    pid=os.getpid(),
                    security={
                        name: fields[name].strip()
                        for name in (
                            "Uid",
                            "Gid",
                            "CapInh",
                            "CapPrm",
                            "CapEff",
                            "CapBnd",
                            "CapAmb",
                            "NoNewPrivs",
                            "Seccomp",
                        )
                    },
                )
            ),
            file=sys.stderr,
            flush=True,
        )

    security_state("manager-start")
    manager_security = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
    )
    assert int(manager_security["CapEff"].strip(), 16) == 0xC0
    assert int(manager_security["CapPrm"].strip(), 16) == 0xC0
    assert int(manager_security["CapBnd"].strip(), 16) == 0xC0
    assert int(manager_security["CapAmb"].strip(), 16) == 0x80
    account = json.loads((STATE / "identity.json").read_text())
    manager = Manager()
    first = manager.create("a" * 32)
    second = manager.create("b" * 32)
    try:
        manager.create("c" * 32)
    except Denied:
        pass
    else:
        raise AssertionError("Concurrent group quota not enforced")
    try:
        first.attach_root_child(os.getpid())
    except Denied:
        pass
    else:
        raise AssertionError("Arbitrary PID accepted")
    assert (first.path / "memory.max").read_text().strip() == "134217728"
    assert (first.path / "pids.max").read_text().strip() == "24"
    assert (first.path / "cpu.max").read_text().strip() == "20000 100000"
    assert (first.path / "memory.oom.group").read_text().strip() == "1"
    reader, writer = os.pipe()
    ready_reader, ready_writer = os.pipe()
    parent_pid = os.getpid()
    child = os.fork()
    if child == 0:
        os.close(writer)
        os.close(ready_reader)
        assert os.read(reader, 1) == b"g"
        security_state("child-before-drop")
        drop(action_id="a" * 32, caller_uid=account["uid"], parent_pid=parent_pid)
        security_state("child-after-user-drop")
        death_signal = ctypes.c_int()
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.prctl(2, ctypes.byref(death_signal), 0, 0, 0) == 0
        assert death_signal.value == 9
        child_security = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        )
        assert all(
            int(child_security[name].strip(), 16) == 0
            for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
        assert child_security["NoNewPrivs"].strip() == "1"
        detached_reader, detached_writer = os.pipe()
        grandchild = os.fork()
        if grandchild == 0:
            os.close(detached_reader)
            os.setsid()
            os.write(detached_writer, b"d")
            os.close(detached_writer)
            time.sleep(60)
            os._exit(0)
        os.close(detached_writer)
        assert os.read(detached_reader, 1) == b"d"
        os.close(detached_reader)
        os.write(ready_writer, b"r")
        time.sleep(60)
        os._exit(0)
    os.close(reader)
    os.close(ready_writer)
    try:
        first.attach_root_child(child)
        assert str(child) in (first.path / "cgroup.procs").read_text().split()
        os.write(writer, b"g")
        os.close(writer)
        writer = -1
        assert os.read(ready_reader, 1) == b"r"
        members = set((first.path / "cgroup.procs").read_text().split())
        assert len(members) == 2 and str(child) in members
        detached_pid = int((members - {str(child)}).pop())
        assert os.getsid(detached_pid) == detached_pid
        assert first.populated()
        assert (
            Path(f"/proc/{child}/status").read_text().split("Uid:", 1)[1].splitlines()[0].split()
            == [str(account["uid"])] * 4
        )
        first.kill_and_close()
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == -9
        assert not first.path.exists()
        try:
            manager.create("a" * 32)
        except Denied:
            pass
        else:
            raise AssertionError("Closed action ID reused")
        second.kill_and_close()
        assert set((ROOT / "control" / "cgroup.procs").read_text().split()) == {str(os.getpid())}
        workspace = Path(account["workspace"])
        root_fd = os.open(workspace, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        cwd_fd = os.dup(root_fd)
        sequence = 0

        def observe(name, *, contents=False):
            # Observe as the directory owner in a separate fixed-code process;
            # the supervisor has no DAC override and keeps its credentials.
            observation_r, observation_w = os.pipe()
            observer = os.fork()
            if observer == 0:
                try:
                    for entry in os.listdir("/proc/self/fd"):
                        fd = int(entry)
                        if fd not in {0, 1, 2, observation_w}:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
                    broker = pwd.getpwnam("mano-broker")
                    os.setgroups([])
                    os.setgid(broker.pw_gid)
                    os.setuid(broker.pw_uid)
                    value = (
                        (workspace / name).read_text() if contents else (workspace / name).exists()
                    )
                    os.write(observation_w, json.dumps(value).encode())
                    os._exit(0)
                except BaseException:
                    os._exit(125)
            os.close(observation_w)
            packet = os.read(observation_r, 4096)
            os.close(observation_r)
            _, observer_status = os.waitpid(observer, 0)
            assert os.waitstatus_to_exitcode(observer_status) == 0
            return json.loads(packet)

        def prepare(source):
            global sequence
            sequence += 1
            request = ActionRequest.parse(
                canonical(
                    dict(
                        schema_version="1.0",
                        task_id="a" * 32,
                        grant_id="b" * 32,
                        resource_id="c" * 32,
                        capability="terminal.run",
                        args=dict(
                            argv=["/usr/bin/python3", "-c", source], cwd=".", timeout_seconds=10
                        ),
                        idempotency_key=f"operator-{sequence}",
                        reason="operator fixture; no broker grant",
                    )
                ).encode()
            )
            return Child(
                manager,
                LaunchAdmission(f"{sequence:032x}", account["uid"], request, root_fd, cwd_fd),
            )

        def completed(job):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                result = job.poll()
                if job.closed:
                    assert job.state == "finished" and result is not None
                    return result
                time.sleep(0.01)
            job.cancel()
            raise AssertionError("Supervised child completion deadline")

        normal = prepare(
            "from pathlib import Path;Path('/workspace/started').write_text('1');print(42)"
        )
        assert normal.state == "prepared" and not observe("started")
        normal.start(lambda: True)  # Operator fixture authority, not a broker journal grant.
        try:
            normal.start(lambda: True)
        except Denied:
            pass
        else:
            raise AssertionError("Start replay accepted")
        observed = completed(normal)
        assert observed.return_code == 0 and observed.stdout.strip() == b"42", observed.stderr
        assert observe("started", contents=True) == "1"
        denied = prepare("from pathlib import Path;Path('/workspace/denied').write_text('bad')")
        try:
            denied.start(lambda: False)
        except Denied:
            pass
        else:
            raise AssertionError("False start authority accepted")
        assert denied.state == "not-started" and not observe("denied")
        expired = prepare("from pathlib import Path;Path('/workspace/expired').write_text('bad')")
        time.sleep(5.1)
        try:
            expired.start(lambda: True)
        except Denied:
            pass
        else:
            raise AssertionError("Expired prepared child started")
        assert expired.state == "not-started" and not observe("expired")
        large = prepare("import os;os.write(1,b'x'*65536);os.write(2,b'y'*65536)")
        large.start(lambda: True)
        big = completed(large)
        assert big.return_code == 0 and len(big.stdout) == len(big.stderr) == 65536
        active = prepare(
            "import time;from pathlib import Path;"
            "Path('/workspace/active').write_text('1');time.sleep(60)"
        )
        active.start(lambda: True)
        deadline = time.monotonic() + 5
        while not observe("active") and time.monotonic() < deadline:
            time.sleep(0.01)
        assert observe("active")
        active.cancel()
        assert active.state == "unknown" and active.result is None
        before_fds = len(list(Path("/proc/self/fd").iterdir()))
        sequence += 1
        bad_request = ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id="a" * 32,
                    grant_id="b" * 32,
                    resource_id="c" * 32,
                    capability="terminal.run",
                    args=dict(argv=["/usr/bin/true"], cwd=".", timeout_seconds=5),
                    idempotency_key="bad-fd-fixture",
                    reason="operator failure fixture",
                )
            ).encode()
        )
        try:
            Child(
                manager,
                LaunchAdmission(f"{sequence:032x}", account["uid"], bad_request, -1, cwd_fd),
            )
        except OSError:
            pass
        else:
            raise AssertionError("Invalid admission FD accepted")
        assert not manager.jobs
        assert len(list(Path("/proc/self/fd").iterdir())) == before_fds
        os.close(root_fd)
        os.close(cwd_fd)
        assert not manager.jobs
        manager.close()
        assert not (ROOT / "control").exists()
        (STATE / "report.json").write_text(
            json.dumps(
                dict(
                    scope="delegated cgroup library in actual root service; no launch endpoint",
                    own_service_only=True,
                    manager_control_separated=True,
                    task_limits=dict(memory_bytes=134217728, pids=24, cpu_quota="20000 100000"),
                    placed_before_credential_drop=True,
                    task_uid=account["uid"],
                    allocated_identity_drop=True,
                    parent_death_signal_set=True,
                    detached_descendant_killed=True,
                    task_group_removed=True,
                    concurrent_quota_denied=True,
                    arbitrary_pid_denied=True,
                    action_reuse_denied=True,
                    manager_survived=True,
                    child_capability_sets_zero=True,
                    manager_capabilities="SETUID|SETGID; ambient SETUID only",
                    supervised_child=dict(
                        blocked_before_start=True,
                        exact_start_once=True,
                        denied_start_no_effect=True,
                        expired_preparation_no_effect=True,
                        failed_allocation_no_fd_or_group_leak=True,
                        operator_workspace_effect_observed=True,
                        both_64k_stream_report_drained=True,
                        active_cancel_unknown=True,
                        all_groups_removed=True,
                        broker_grant_integrated=False,
                    ),
                    no_task_argv_executed=False,
                    model_connected=False,
                ),
                indent=2,
            )
        )
    finally:
        if writer >= 0:
            os.close(writer)
        os.close(ready_reader)
    sys.exit(0)

assert not sys.argv[1:]
assert not STATE.exists() and not CODE.exists() and not UNIT_FILE.exists() and not LOCK.exists()
assert not BASE.exists() and not GUARD.exists()
assert "mano-broker" not in {p.pw_name for p in pwd.getpwall()}
assert "mano-request" not in {g.gr_name for g in grp.getgrall()}
created = []
group_created = False
try:
    subprocess.run(["groupadd", "mano-request"], check=True)
    group_created = True
    subprocess.run(["useradd", "--system", "--no-create-home", "mano-broker"], check=True)
    created.append("mano-broker")
    identity = allocate_identity()
    created.append(identity.name)
    workspace, workspace_fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    os.close(workspace_fd)
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
    STATE.mkdir(mode=0o700)
    (STATE / "identity.json").write_text(
        json.dumps({"uid": identity.uid, "gid": identity.gid, "workspace": str(workspace)})
    )
    (STATE / "identity.json").chmod(0o600)
    CODE.mkdir(mode=0o755)
    shutil.copytree(
        "/opt/mano-lab/src/mano_broker",
        CODE / "mano_broker",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(
        "/opt/mano-lab/src/mano_lab",
        CODE / "mano_lab",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copyfile(__file__, CODE / "probe.py")
    for file in CODE.rglob("*.py"):
        file.chmod(0o444)
    UNIT_FILE.write_text("""[Unit]
Description=Disposable mano delegated cgroup proof
[Service]
Type=exec
User=root
ExecStart=/usr/bin/python3 /usr/lib/mano-os/probe.py --inner
Environment=PYTHONPATH=/usr/lib/mano-os
Environment=PYTHONDONTWRITEBYTECODE=1
Delegate=cpu memory pids
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_SETUID
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=no
ReadWritePaths=/sys/fs/cgroup/system.slice/mano-launcher.service /run/mano-delegation-ci
ReadWritePaths=/var/lib/mano-workspaces
MemoryMax=320M
TasksMax=64
CPUQuota=60%
KillMode=control-group
TimeoutStartSec=15
TimeoutStopSec=5
RuntimeMaxSec=30
""")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "start", "mano-launcher.service"], check=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if (STATE / "report.json").exists():
            print((STATE / "report.json").read_text())
            break
        result = subprocess.check_output(
            ["systemctl", "show", "mano-launcher.service", "--property=Result", "--value"],
            text=True,
        ).strip()
        assert result == "success", result
        time.sleep(0.1)
    else:
        raise AssertionError("Delegated service report unavailable")
except BaseException:
    subprocess.run(
        ["journalctl", "-u", "mano-launcher.service", "--no-pager", "-n", "80"],
        stdout=sys.stderr,
        check=False,
    )
    raise
finally:
    subprocess.run(["systemctl", "stop", "mano-launcher.service"], check=False, capture_output=True)
    UNIT_FILE.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    subprocess.run(
        ["systemctl", "reset-failed", "mano-launcher.service"], check=False, capture_output=True
    )
    if CODE.exists():
        shutil.rmtree(CODE)
    if STATE.exists():
        shutil.rmtree(STATE)
    if BASE.exists():
        shutil.rmtree(BASE)
    GUARD.unlink(missing_ok=True)

    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
    if group_created:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)
