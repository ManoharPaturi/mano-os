#!/usr/bin/env python3
"""Operator journal client against the installed launcher in the disposable VM."""

import base64
import json
import os
import pwd
import subprocess
import time
from pathlib import Path

from mano_broker.executor import Executor
from mano_broker.launch_client import Client
from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.registry import Registry
from mano_broker.state import Denied, State

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
registry = Registry()
client = Client()
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
    executor = Executor(state, registry, client, boot_id="daemon")

    def prepare(source, key):
        args = dict(argv=["/usr/bin/python3", "-c", source], cwd=".", timeout_seconds=10)
        grant = state.issue_grant(task, approved_human_uid=1002, approved_args=args,
            capability=Capability.RUN, resource_id=resource, expires=time.monotonic() + 30,
            max_count=1, memory_bytes=128 * 1024**2, pids=24, cpu_percent=20,
            max_timeout_seconds=10)
        request = ActionRequest.parse(canonical(dict(schema_version="1.0", task_id=task,
            resource_id=resource, grant_id=grant, capability="terminal.run", args=args,
            idempotency_key=key, reason="production daemon operator approval fixture")).encode())
        row, lease = registry.prepare(state, request, caller_uid=identity["uid"],
                                      now=time.monotonic(), boot_id="daemon")
        assert lease is not None
        return row["id"]

    action = prepare("print('production-daemon-ok')", "daemon-once")
    executor.launch(action)
    handle = executor.jobs[action].copy()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = executor.poll(action)
        if response["state"] == "finished":
            break
        time.sleep(0.01)
    row = state.db.execute("SELECT state,verified FROM actions WHERE id=?", (action,)).fetchone()
    assert tuple(row) == ("done", 0)
    output = client.exchange("control", dict(schema_version="1.0", operation="read_output",
        body=handle | dict(stream="stdout", offset=0, length=64)))
    assert base64.b64decode(output["data"]).strip() == b"production-daemon-ok"
    assert output["effect_verified"] is False
    active = prepare("import time;time.sleep(60)", "daemon-stop")
    executor.launch(active)
    state.emergency_stop()
    try:
        executor.poll(active)
    except Denied:
        pass
    else:
        raise AssertionError("Stopped task accepted")
    row = state.db.execute("SELECT state FROM actions WHERE id=?", (active,)).fetchone()
    assert row[0] == "unknown"
    assert not registry.leases
    print(json.dumps(dict(production_launcher_daemon=True, daemon_journal_execution=True,
        daemon_stop_cancellation=True, pam_authorization=False, model_connected=False)))
finally:
    registry.close()
    client.close()
    state.close()
