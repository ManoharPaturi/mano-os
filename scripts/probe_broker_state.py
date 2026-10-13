#!/usr/bin/env python3
"""Real private journal permissions/restart probe in the disposable Debian guest."""

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State

ROOT = Path("/opt/mano-lab")
DIRECTORY = Path("/var/lib/mano-broker/phase1-state-probe")
assert (
    os.geteuid() == 0 and Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
)
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not DIRECTORY.exists(), "Refusing existing journal fixture"
state = State(DIRECTORY)
boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
resource = "a" * 32
try:
    task = state.create_task(
        human_uid=1002,
        caller_uid=1004,
        mode="auto",
        resource_id=resource,
        classification="internal",
        boot_id=boot,
    )
    grant = state.issue_grant(
        task,
        approved_human_uid=1002,
        capability="terminal.run",
        resource_id=resource,
        expires=time.monotonic() + 30,
        max_count=1,
        memory_bytes=64 * 1024**2,
        pids=16,
        cpu_percent=20,
        max_timeout_seconds=10,
    )
    packet = canonical(
        {
            "schema_version": "1.0",
            "task_id": task,
            "grant_id": grant,
            "capability": "terminal.run",
            "resource_id": resource,
            "args": {"argv": ["true"], "cwd": ".", "timeout_seconds": 10},
            "idempotency_key": "fixed-ci-action",
            "reason": "durable state probe",
        }
    ).encode()
    request = ActionRequest.parse(packet)
    state.close()
    writer = os.fork()
    if writer == 0:
        try:
            child = State(DIRECTORY)
            action, fresh = child.authorize(
                request, caller_uid=1004, now=time.monotonic(), boot_id=boot
            )
            assert fresh
            child.start(action["id"], now=time.monotonic(), boot_id=boot)
            os._exit(0)  # Abrupt writer exit after durable executing commit, no close/destructors.
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(writer, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    state = State(DIRECTORY)
    action = state.db.execute("SELECT * FROM actions WHERE task_id=?", (task,)).fetchone()
    assert state.recover() == 1
    replay, fresh = state.authorize(request, caller_uid=1004, now=time.monotonic(), boot_id=boot)
    assert not fresh and replay["state"] == "unknown" and replay["verified"] == 0
    try:
        state.start(action["id"], now=time.monotonic(), boot_id=boot)
    except Denied:
        pass
    else:
        raise AssertionError("Unknown action redispatched")
    before = hashlib.sha256((DIRECTORY / "state.sqlite3").read_bytes()).hexdigest()
    attacks = []
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        for operation in ("read", "write"):
            source = (
                "import sys,errno; from pathlib import Path\n"
                "try:\n"
                " p=Path(sys.argv[1])\n"
                " if sys.argv[2]=='read': p.read_bytes()\n"
                " else: p.open('r+b')\n"
                "except PermissionError as e:\n"
                " assert e.errno==errno.EACCES;sys.exit(0)\n"
                "sys.exit(1)\n"
            )
            result = subprocess.run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    actor,
                    "--",
                    "python3",
                    "-c",
                    source,
                    str(DIRECTORY / "state.sqlite3"),
                    operation,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            attacks.append({"actor": actor, "operation": operation, "kernel_errno": "EACCES"})
    assert hashlib.sha256((DIRECTORY / "state.sqlite3").read_bytes()).hexdigest() == before
    state.emergency_stop()
    state.close()
    state = State(DIRECTORY)
    assert state.meta("latched") == 1 and state.meta("epoch") == 1
    report = {
        "scope": "broker state library; transport/executor not integrated",
        "restart_unknown_not_replayed": True,
        "abrupt_writer_exit_verified": True,
        "journal_owner_uid": DIRECTORY.stat().st_uid,
        "directory_mode": oct(DIRECTORY.stat().st_mode & 0o777),
        "database_mode": oct((DIRECTORY / "state.sqlite3").stat().st_mode & 0o777),
        "kernel_denials": attacks,
        "denial_attempts_preserved_database_hash": True,
        "durable_stop_latch": True,
        "model_connected": False,
        "production_execution_authorized": False,
    }
    print(json.dumps(report, indent=2))
finally:
    state.close()
    shutil.rmtree(DIRECTORY)
