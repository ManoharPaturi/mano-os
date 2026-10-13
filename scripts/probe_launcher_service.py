#!/usr/bin/env python3
"""Operator journal client against the installed launcher in the disposable VM."""

import base64
import errno
import hashlib
import json
import os
import pwd
import subprocess
import time
from pathlib import Path

from mano_broker.artifacts import Store
from mano_broker.ipc import Peer
from mano_broker.launch_client import Client
from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.runtime import Runtime
from mano_broker.state import State

assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm", "qemu"
}
identity = json.loads(Path("/run/mano-delegation-ci/identity.json").read_text())
broker = pwd.getpwnam("mano-broker")
os.setgroups([])
os.setgid(broker.pw_gid)
os.setuid(broker.pw_uid)
state = State(Path("/run/mano-journal-ci") / "daemon")
client = Client()
runtime = Runtime(state, boot_id="daemon", launcher=client)
registry = runtime.registry
artifacts = Store()
try:
    fd = os.open(identity["workspace"], os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        resource = registry.register(
            fd, human_uid=1002, caller_uid=identity["uid"], boot_id="daemon"
        )
    finally:
        os.close(fd)
    task = state.create_task(human_uid=1002, caller_uid=identity["uid"], mode=Mode.AUTO,
                            resource_id=resource, classification="internal", boot_id="daemon")
    registry.resources[resource].task_id = task
    executor = runtime.executor

    def prepare(source, key):
        args = dict(argv=["/usr/bin/python3", "-c", source], cwd=".", timeout_seconds=10)
        grant = state.issue_grant(task, approved_human_uid=1002, approved_args=args,
            capability=Capability.RUN, resource_id=resource, expires=time.monotonic() + 30,
            max_count=1, memory_bytes=128 * 1024**2, pids=24, cpu_percent=20,
            max_timeout_seconds=10)
        request = ActionRequest.parse(canonical(dict(schema_version="1.0", task_id=task,
            resource_id=resource, grant_id=grant, capability="terminal.run", args=args,
            idempotency_key=key, reason="production daemon operator approval fixture")).encode())
        response = runtime.dispatch(canonical(dict(schema_version="1.0", operation="propose",
            body=request.body())).encode(),
            peer=Peer(os.getpid(), identity["uid"], identity["gid"]),
            now=time.monotonic())
        assert response["fresh"]
        return response["action"]["id"]

    action = prepare("from pathlib import Path;"
        "Path('/workspace/captured-result').write_bytes(b'sealed-bytes');"
        "print('production-daemon-ok')", "daemon-once")
    runtime.tick()
    if action not in executor.jobs:
        events = state.db.execute(
            "SELECT event,details_json FROM events WHERE action_id=?", (action,)
        ).fetchall()
        raise AssertionError("Dispatch did not retain job: " + repr([tuple(e) for e in events]))
    handle = executor.jobs[action].copy()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        runtime.tick()
        response = client.exchange("control", dict(schema_version="1.0", operation="status",
                                                   body=handle))
        row = state.db.execute(
            "SELECT state,verified FROM actions WHERE id=?", (action,)
        ).fetchone()
        if response["state"] == "finished" and tuple(row) == ("done", 0):
            break
        time.sleep(0.25)  # At most eight control packets/sec, below the ten/sec budget.
    row = state.db.execute("SELECT state,verified FROM actions WHERE id=?", (action,)).fetchone()
    assert tuple(row) == ("done", 0)
    assert response["state"] == "finished"
    output = client.exchange("control", dict(schema_version="1.0", operation="read_output",
        body=handle | dict(stream="stdout", offset=0, length=64)))
    assert base64.b64decode(output["data"]).strip() == b"production-daemon-ok"
    assert output["effect_verified"] is False
    artifact = artifacts.capture(state, registry, action, "captured-result", boot_id="daemon")
    sealed_fd = artifacts.items[artifact["artifact_id"]].fd
    Path(identity["workspace"], "captured-result").write_bytes(b"source-was-mutated")
    assert os.pread(sealed_fd, 64, 0) == b"sealed-bytes"
    assert artifact["sha256"] == hashlib.sha256(b"sealed-bytes").hexdigest()
    assert artifact["effect_verified"] is False
    for mutation in (lambda: os.pwrite(sealed_fd, b"x", 0), lambda: os.ftruncate(sealed_fd, 0)):
        try:
            mutation()
        except OSError as error:
            assert error.errno == errno.EPERM
        else:
            raise AssertionError("Sealed artifact mutated")
    active = prepare("import time;time.sleep(60)", "daemon-stop")
    runtime.tick()
    state.emergency_stop()
    runtime.tick()
    assert active not in executor.jobs
    row = state.db.execute("SELECT state FROM actions WHERE id=?", (active,)).fetchone()
    assert row[0] == "unknown"
    assert not registry.leases
    print(json.dumps(dict(production_launcher_daemon=True, daemon_journal_execution=True,
        daemon_stop_cancellation=True, runtime_terminal_scheduling=True,
        runtime_caller_metadata_synthetic=True, sealed_artifact_custody=True,
        artifact_source_mutation_isolated=True, artifact_write_and_truncate_denied=True,
        artifact_effect_verified=False, pam_authorization=False, model_connected=False)))
finally:
    artifacts.close()
    runtime.close()
    state.close()
