"""Actual signed catalog/PAM/public SDK forecasts, guarded disposable Debian only."""

import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import time
from pathlib import Path

CLIENT = """import json,sys,time
from mano_core.broker import BrokerClient,read_terminal_output
from mano_core.packages import PackagePlan
value=json.load(sys.stdin);transport=BrokerClient()
def client(packet):
 time.sleep(.12)
 return transport(packet)
try:
 worker=PackagePlan.start(client,proposed=value['proposal'],grant_id=value['grant_id'])
 if value.get('start_only'):
  print(json.dumps(dict(action_id=worker.action_id)));sys.exit(0)
 deadline=time.monotonic()+68
 while time.monotonic()<deadline:
  state=worker.status()
  if state['state'] in {'done','failed','unknown'}:break
  time.sleep(.12)
 if state['state']=='done':result=worker.result()
 else:
  assert state['state']=='failed',state
  failed=read_terminal_output(client,task_id=worker.task_id,action_id=worker.action_id)
  assert failed['metadata']['return_code']==2
  assert not failed['stdout']
  failure=json.loads(failed['stderr'])
  assert failure['error']=='package-plan-unavailable'
  assert failure['stage'] in {'admission','catalog','import','cache','resolve','forecast','recheck'}
  result=dict(failed=True,metadata=failed['metadata'])
 print(json.dumps(dict(action_id=worker.action_id,state=state['state'],result=result)))
finally:transport.close()
"""


def guard():
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
        "qemu",
        "kvm",
    }


def client(identity, proposal, grant_id, *, start_only=False):
    observed = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            identity.name,
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "LANG=C.UTF-8",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPATH=/usr/lib/mano-os",
            "python3",
            "-c",
            CLIENT,
        ],
        text=True,
        capture_output=True,
        input=json.dumps(dict(proposal=proposal, grant_id=grant_id, start_only=start_only)),
        timeout=75,
    )
    assert observed.returncode == 0, (observed.stdout, observed.stderr)
    return json.loads(observed.stdout)


def approve(rpc, human, identity, password, proposed):
    pending = rpc(
        "request",
        dict(schema_version="1.0", operation="request_approval", body=proposed),
        actor=identity.name,
    )["approval"]
    assert pending["state"] == "pending"
    view = human(dict(mode="view", id=pending["approval_id"]))["view"]
    assert view["args"] == proposed["args"]
    assert view["package_scope"]["installation_authorized"] is False
    assert view["package_scope"]["signed_indexes_verified"] is True
    granted = human(dict(mode="confirm", view=view, password=password))
    assert granted["ok"]
    return granted["grant_id"]


def run(rpc, human, identity, password):
    guard()
    from mano_broker.package_catalog import BASE, current_status, load, summary
    from mano_broker.workspaces import create_workspace
    from mano_core.packages import proposal

    refreshed = subprocess.run(
        [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/sbin:/usr/bin:/bin",
            "LANG=C.UTF-8",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3",
            "-m",
            "mano_runtime.package_catalog",
        ],
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert refreshed.returncode == 0, (refreshed.stdout, refreshed.stderr)
    catalog = summary()
    catalog_manifest = load(catalog["catalog_id"])[1]
    assert json.loads(refreshed.stdout)["catalog_id"] == catalog["catalog_id"]
    workspace, fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    os.close(fd)
    task = rpc(
        "provision",
        dict(
            schema_version="1.0",
            operation="provision_task",
            body=dict(
                human_uid=1002,
                caller_uid=identity.uid,
                mode="supervised",
                classification="internal",
            ),
        ),
        actor="root",
        directory=workspace,
    )
    assert task["ok"]
    public_catalog = dict(
        schema_version="1.0",
        operation="package_catalog",
        body=dict(task_id=task["task_id"], resource_id=task["resource_id"]),
    )
    assert rpc("request", public_catalog, actor=identity.name)["catalog"] == catalog
    assert rpc("request", public_catalog)["ok"] is False
    malicious = "from pathlib import Path;Path('/workspace/package-config-canary').touch()\n"
    for filename in ("apt.py", "sitecustomize.py"):
        (workspace / filename).write_text(malicious)
    (workspace / "apt.conf").write_text(
        'DPkg::Pre-Invoke { "touch /workspace/package-config-canary"; };'
    )
    initial = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in workspace.iterdir()
    }
    status = current_status()
    records = {}
    for key, names in (
        ("dependency-plan", ["cowsay", "sl"]),
        ("installed", ["bash"]),
        ("unknown", ["mano-no-such-package-ci"]),
    ):
        proposed = proposal(
            task_id=task["task_id"],
            resource_id=task["resource_id"],
            names=names,
            catalog_id=catalog["catalog_id"],
            key="package-" + key,
            reason="Preview exact package changes",
        )
        grant = approve(rpc, human, identity, password, proposed)
        record = client(identity, proposed, grant)
        if key == "unknown":
            assert record["state"] == "failed"
        else:
            assert record["state"] == "done"
            plan = record["result"]["plan"]
            assert plan["names"] == names and plan["catalog_id"] == catalog["catalog_id"]
            assert plan["install_authorized"] is False and plan["network_used"] is False
            assert plan["maintainer_scripts_executed"] is False
            if key == "dependency-plan":
                assert {"cowsay", "sl"} <= {row["name"] for row in plan["changes"]}
                reference = subprocess.run(
                    [
                        "/usr/bin/env",
                        "-i",
                        "PATH=/usr/bin:/bin",
                        "LANG=C.UTF-8",
                        "/usr/bin/apt-get",
                        "--simulate",
                        "--no-install-recommends",
                        "--no-remove",
                        "-o",
                        "Dir::Cache::pkgcache=",
                        "-o",
                        "Dir::Cache::srcpkgcache=",
                        "install",
                        *names,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=True,
                )
                oracle = {}
                for line in reference.stdout.splitlines():
                    match = re.match(r"^Inst ([a-z0-9+.-]+)(?: \[[^\]]+\])? \(([^ ]+)", line)
                    if match:
                        oracle[match[1]] = match[2]
                assert oracle == {row["name"]: row["candidate"] for row in plan["changes"]}
                record["independent_apt_get_simulation_versions"] = oracle
            else:
                assert plan["requested"][0]["installed"] is not None
        assert current_status() == status
        assert {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in workspace.iterdir()
        } == initial
        replay = rpc(
            "request",
            dict(schema_version="1.0", operation="propose", body=proposed | dict(grant_id=grant)),
            actor=identity.name,
        )
        assert replay["ok"] and replay["fresh"] is False
        assert replay["action"]["id"] == record["action_id"]
        wrong = dict(
            schema_version="1.0",
            operation="terminal_output",
            body=dict(task_id=task["task_id"], action_id=record["action_id"]),
        )
        assert rpc("request", wrong)["ok"] is False
        records[key] = record
    stale = proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        names=["sl"],
        catalog_id=catalog["catalog_id"],
        key="package-stale-catalog",
        reason="Reject changed catalog",
    )
    stale_grant = approve(rpc, human, identity, password, stale)
    active = BASE / "active.json"
    original = active.read_bytes()
    try:
        active.write_text(json.dumps(dict(catalog_id="0" * 64)))
        rejected = rpc(
            "request",
            dict(
                schema_version="1.0", operation="propose", body=stale | dict(grant_id=stale_grant)
            ),
            actor=identity.name,
        )
        assert rejected["ok"] is False
        with sqlite3.connect(
            "file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro", uri=True
        ) as database:
            assert (
                database.execute("SELECT used FROM grants WHERE id=?", (stale_grant,)).fetchone()[0]
                == 0
            )
            assert (
                database.execute(
                    "SELECT count(*) FROM actions WHERE grant_id=?", (stale_grant,)
                ).fetchone()[0]
                == 0
            )
    finally:
        active.write_bytes(original)
    corrupt = proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        names=["sl"],
        catalog_id=catalog["catalog_id"],
        key="package-corrupt-input",
        reason="Reject changed input bytes",
    )
    corrupt_grant = approve(rpc, human, identity, password, corrupt)
    root, _ = load(catalog["catalog_id"])
    saved = root / "inputs/status"
    original = saved.read_bytes()
    try:
        saved.write_bytes(b"changed after snapshot approval")
        corrupted = client(identity, corrupt, corrupt_grant)
        assert corrupted["state"] == "failed"
    finally:
        saved.write_bytes(original)
    assert current_status() == status
    assert {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in workspace.iterdir()
    } == initial
    records["corrupt-input"] = corrupted
    return dict(
        catalog=catalog,
        catalog_manifest=catalog_manifest,
        records=records,
        native_pam=True,
        public_sdk=True,
        actual_solver=True,
        dpkg_state_unchanged=True,
        workspace_unchanged=True,
        malicious_workspace_config_ignored=True,
        unknown_package_failed=True,
        stale_catalog_denied_without_grant_use=True,
        corrupted_input_failed_without_effect=True,
        completed_replay_no_solver=True,
        wrong_caller_denied=True,
        install_authorized=False,
        model_disclosure=False,
        paid_execution=False,
    )


def stop_probe(rpc, human, identity, password, task, broker_pid, launcher_pid, stop_client):
    guard()
    from mano_broker.package_catalog import current_status, summary
    from mano_core.packages import proposal
    from mano_protocol.stop_state import snapshot

    view = human(dict(mode="rearm_view"))["view"]
    rearmed = human(dict(mode="rearm_confirm", view=view, password=password))
    assert rearmed["ok"] and rearmed["rearmed"]
    current = summary()
    proposed = proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        names=["cowsay", "sl"],
        catalog_id=current["catalog_id"],
        key="package-frozen-stop",
        reason="Stop a live read-only package solver",
    )
    grant = approve(rpc, human, identity, password, proposed)
    launched = client(identity, proposed, grant, start_only=True)
    action = launched["action_id"]
    group = Path("/sys/fs/cgroup/system.slice/mano-launcher.service") / ("task-" + action)
    deadline = time.monotonic() + 15
    frozen = None
    while time.monotonic() < deadline and frozen is None:
        try:
            pids = [int(value) for value in (group / "cgroup.procs").read_text().split()]
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        for pid in pids:
            try:
                proc = Path("/proc") / str(pid)
                argv = proc.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                if (
                    argv[:3] != [b"/usr/bin/python3", b"-I", b"/package-solver.py"]
                    or proc.stat().st_uid != identity.uid
                    or proc.joinpath("exe").resolve(strict=True)
                    != Path("/usr/bin/python3").resolve(strict=True)
                ):
                    continue
                pidfd = os.pidfd_open(pid)
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                    status = proc.joinpath("status").read_text()
                    assert "T" in next(
                        line for line in status.splitlines() if line.startswith("State:")
                    )
                    mounts = proc.joinpath("mountinfo").read_text().splitlines()
                    for mount in ("/workspace", "/task-cwd", "/catalog"):
                        assert any(
                            line.split()[4] == mount and "ro" in line.split()[5].split(",")
                            for line in mounts
                        )
                    namespaces = {
                        kind: os.readlink(proc / "ns" / kind) for kind in ("net", "mnt", "ipc")
                    }
                    assert all(
                        value != os.readlink("/proc/self/ns/" + kind)
                        for kind, value in namespaces.items()
                    )
                    envkeys = [
                        row.split(b"=", 1)[0].decode()
                        for row in proc.joinpath("environ").read_bytes().split(b"\0")
                        if row
                    ]
                    assert not set(envkeys) & {
                        "APT_CONFIG",
                        "PYTHONPATH",
                        "GNUPGHOME",
                        "LD_PRELOAD",
                        "DBUS_SESSION_BUS_ADDRESS",
                        "OPENAI_API_KEY",
                    }
                    frozen = dict(
                        pid=pid,
                        executable=str(proc.joinpath("exe").resolve(strict=True)),
                        namespaces=namespaces,
                        environment_keys=envkeys,
                        read_only_mounts=True,
                    )
                finally:
                    os.close(pidfd)
                break
            except (FileNotFoundError, ProcessLookupError):
                continue
        if frozen is None:
            time.sleep(0.02)
    assert frozen is not None, "Actual fixed package solver was not observed"
    state_before = current_status()
    authorities = [broker_pid, launcher_pid]
    subprocess.run(["kill", "-STOP", *map(str, authorities)], check=True)
    try:
        stopped = subprocess.run(
            ["/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client)],
            text=True,
            capture_output=True,
            timeout=5,
            check=True,
        )
        assert "Emergency Stop acknowledged" in stopped.stdout
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not group.exists() or "populated 0" in (group / "cgroup.events").read_text():
                break
            time.sleep(0.05)
        assert not group.exists() or "populated 0" in (group / "cgroup.events").read_text()
        for pid in authorities:
            assert "T" in next(
                line
                for line in Path("/proc", str(pid), "status").read_text().splitlines()
                if line.startswith("State:")
            )
    finally:
        subprocess.run(["kill", "-CONT", *map(str, authorities)], check=False)
    query = dict(
        schema_version="1.0",
        operation="status",
        body=dict(task_id=task["task_id"], action_id=action),
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        observed = rpc("request", query, actor=identity.name)["action"]
        if observed["state"] == "unknown":
            break
        time.sleep(0.15)
    assert observed["state"] == "unknown" and observed["verified"] == 0
    assert (
        rpc(
            "request",
            dict(schema_version="1.0", operation="propose", body=proposed | dict(grant_id=grant)),
            actor=identity.name,
        )["ok"]
        is False
    )
    subprocess.run(["systemctl", "restart", "mano-broker.service"], check=True, timeout=10)
    after = rpc("request", query, actor=identity.name)["action"]
    assert after["state"] == "unknown" and after["verified"] == 0
    assert current_status() == state_before
    native = snapshot()
    assert native.latched
    return dict(
        action_id=action,
        task_id=task["task_id"],
        solver=frozen,
        native_stop_with_broker_and_launcher_frozen=True,
        solver_group_drained=True,
        restart_unknown_no_replay=True,
        dpkg_state_unchanged=True,
        install_authorized=False,
        stop_generation=native.generation,
    )
