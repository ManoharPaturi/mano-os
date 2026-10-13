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
from mano_broker.state import Denied

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
        assert Path(f"/proc/{child}/status").read_text().split("Uid:", 1)[1].splitlines()[
            0
        ].split() == [str(account["uid"])] * 4
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
                    no_task_argv_executed=True,
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
    STATE.mkdir(mode=0o700)
    (STATE / "identity.json").write_text(json.dumps({"uid": identity.uid, "gid": identity.gid}))
    (STATE / "identity.json").chmod(0o600)
    CODE.mkdir(mode=0o755)
    shutil.copytree(
        "/opt/mano-lab/src/mano_broker",
        CODE / "mano_broker",
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

    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
    if group_created:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)
