#!/usr/bin/env python3
"""Real delegated service cgroup custody in the disposable VM, no task argv."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mano_broker.cgroups import ROOT, Manager
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
    child = os.fork()
    if child == 0:
        os.close(writer)
        os.close(ready_reader)
        assert os.read(reader, 1) == b"g"
        os.setgroups([])
        os.setgid(1004)
        os.setuid(1004)
        grandchild = os.fork()
        if grandchild == 0:
            os.setsid()
            time.sleep(60)
            os._exit(0)
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
        assert len((first.path / "cgroup.procs").read_text().split()) == 2
        assert first.populated()
        assert Path(f"/proc/{child}/status").read_text().split("Uid:", 1)[1].splitlines()[
            0
        ].split() == ["1004", "1004", "1004", "1004"]
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
                    task_uid=1004,
                    detached_descendant_killed=True,
                    task_group_removed=True,
                    concurrent_quota_denied=True,
                    arbitrary_pid_denied=True,
                    action_reuse_denied=True,
                    manager_survived=True,
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
assert not STATE.exists() and not CODE.exists() and not UNIT_FILE.exists()
try:
    STATE.mkdir(mode=0o700)
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
AmbientCapabilities=
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
