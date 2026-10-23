"""Interrupt actual approved dpkg; Root observer/repair in disposable CI only."""

import hashlib
import json
import os
import select
import signal
import subprocess
import time
from pathlib import Path

from probe_package_apply import GROUP, terminal
from probe_package_plans import approve, client, guard, wait_stopped


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)


def members():
    result = set()
    for path in GROUP.rglob("cgroup.procs"):
        try:
            result.update(map(int, path.read_text().split()))
        except FileNotFoundError:
            pass
    return result


def empty():
    return not GROUP.exists() or "populated 0" in (GROUP / "cgroup.events").read_text()


def wait(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.005)
    raise AssertionError("Actual package interruption witness timed out")


def run(rpc, human, identity, password, ready, launcher_pid, stop_client):
    guard()
    from mano_broker.package_catalog import summary
    from mano_broker.workspaces import create_workspace
    from mano_core.packages import apply_proposal, proposal
    from mano_protocol.actions import ActionRequest, canonical
    from mano_protocol.stop_state import snapshot
    from mano_runtime import package_attempts, recovery
    from mano_runtime.package_operator import ACK, RETIRE

    assert snapshot().latched and empty()
    view = human(dict(mode="rearm_view"))["view"]
    assert human(dict(mode="rearm_confirm", view=view, password=password))["ok"]
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
    planned = proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        names=["sl"],
        catalog_id=summary()["catalog_id"],
        key="actual-dpkg-stop-plan",
        reason="Review signed sl install for disposable interruption test",
    )
    forecast = client(identity, planned, approve(rpc, human, identity, password, planned))
    assert forecast["state"] == "done"
    plan = forecast["result"]["plan"]
    # Keep test-only manual recovery narrow: no upgrade/removal or dependency undo.
    assert len(plan["changes"]) == 1
    change = plan["changes"][0]
    assert change["name"] == "sl" and change["operation"] == "install"
    assert change["installed"] is None
    cached = [
        p
        for p in Path("/var/cache/apt/archives").glob("*.deb")
        if p.stat().st_size == change["download_bytes"]
        and hashlib.sha256(p.read_bytes()).hexdigest() == change["archive_sha256"]
    ]
    assert len(cached) == 1
    before = command(
        "/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${db:Status-Status} ${Version}\n"
    ).stdout
    proposed = apply_proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        forecast_action_id=forecast["action_id"],
        plan_sha256=forecast["result"]["sha256"],
        key="actual-dpkg-stop-apply",
        reason="Interrupt actual approved dpkg in disposable CI",
    )
    pending = rpc(
        "request",
        dict(schema_version="1.0", operation="request_approval", body=proposed),
        actor=identity.name,
    )["approval"]
    review = human(dict(mode="view", id=pending["approval_id"]))["view"]
    assert review["package_apply_scope"]["plan"] == plan
    grant = human(dict(mode="confirm", view=review, password=password))
    assert grant["ok"]
    request = proposed | dict(grant_id=grant["grant_id"])
    request_sha = ActionRequest.parse(canonical(request).encode()).digest
    program = """import json,sys
from mano_core.broker import BrokerClient
from mano_core.packages import PackageApply
body=json.load(sys.stdin); client=BrokerClient()
try:
 worker=PackageApply.start(client,proposed=body['proposed'],grant_id=body['grant'])
 print(json.dumps(dict(action_id=worker.action_id)),flush=True)
finally:client.close()
"""
    child = subprocess.Popen(
        [
            "/usr/sbin/runuser",
            "-u",
            identity.name,
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3",
            "-c",
            program,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child.stdin.write(json.dumps(dict(proposed=proposed, grant=grant["grant_id"])))
    child.stdin.close()
    child.stdin = None
    descriptors = {}
    authorities = (ready(), launcher_pid)
    stop_pid = int(
        command("systemctl", "show", "mano-stopd.service", "--property=MainPID", "--value").stdout
    )
    observed = None
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and observed is None:
            for pid in members():
                proc = Path("/proc") / str(pid)
                try:
                    if proc.joinpath("exe").resolve(strict=True) != Path("/usr/bin/dpkg"):
                        continue
                    fd = os.pidfd_open(pid)
                    descriptors[pid] = fd
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                    wait_stopped(proc)
                    assert proc.joinpath("exe").resolve(strict=True) == Path("/usr/bin/dpkg")
                    fields = dict(
                        line.split(":", 1)
                        for line in proc.joinpath("status").read_text().splitlines()
                    )
                    assert fields["Uid"].split() == ["0"] * 4
                    group = proc.joinpath("cgroup").read_text().strip()
                    assert group.startswith("0::/mano.slice/mano-package.slice/")
                    capabilities = {
                        k: int(fields[k], 16)
                        for k in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")
                    }
                    assert set(capabilities.values()) == {0xDB}
                    observed = dict(
                        pid=pid,
                        executable="/usr/bin/dpkg",
                        uid=0,
                        cgroup=group,
                        argv=[
                            v.decode()
                            for v in proc.joinpath("cmdline")
                            .read_bytes()
                            .rstrip(b"\0")
                            .split(b"\0")
                        ],
                        capabilities=capabilities,
                        kernel_frozen=True,
                    )
                    break
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if observed is None:
                time.sleep(0.001)
        assert observed is not None, (
            "No actual dpkg process observed; synthetic Stop is insufficient"
        )
        # Freeze the controller and every remaining package process too. The
        # independent Root observer and stopd deliberately remain runnable.
        for _unused in range(4):
            for pid in members() | set(authorities):
                if pid not in descriptors:
                    descriptors[pid] = os.pidfd_open(pid)
                signal.pidfd_send_signal(descriptors[pid], signal.SIGSTOP)
                wait_stopped(Path("/proc") / str(pid))
        package_pids = members()
        assert observed["pid"] in package_pids and os.getpid() not in package_pids
        result = command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
        assert "Emergency Stop acknowledged" in result.stdout
        wait(empty)
        for pid in package_pids:
            wait(lambda pid=pid: select.select([descriptors[pid]], [], [], 0)[0])
        for pid in authorities:
            wait_stopped(Path("/proc") / str(pid))
        assert (
            int(
                command(
                    "systemctl", "show", "mano-stopd.service", "--property=MainPID", "--value"
                ).stdout
            )
            == stop_pid
        )
    finally:
        for pid in authorities:
            if pid in descriptors and not select.select([descriptors[pid]], [], [], 0)[0]:
                signal.pidfd_send_signal(descriptors[pid], signal.SIGCONT)
        for fd in descriptors.values():
            os.close(fd)
        if not empty():
            command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
    stdout, stderr = child.communicate(timeout=8)
    assert child.returncode == 0, stderr[-4096:]
    action = json.loads(stdout)["action_id"]
    query = dict(
        schema_version="1.0",
        operation="status",
        body=dict(task_id=task["task_id"], action_id=action),
    )

    def unknown():
        time.sleep(0.15)
        state = rpc("request", query, actor=identity.name)["action"]
        return state if state["state"] == "unknown" else None

    state = wait(unknown)
    assert state["verified"] == 0
    rows = package_attempts.reconcile()
    attempt = next(r for r in rows if r["intent"]["attempt_id"] == action)
    assert attempt["intent"]["request_sha256"] == request_sha
    assert attempt["outcome"]["state"] == "unknown"
    unknown_path = package_attempts.BASE / action / "unknown.json"
    unknown_bytes = unknown_path.read_bytes()
    subprocess.run(["systemctl", "restart", "mano-broker.service"], check=True, timeout=15)
    ready()
    assert unknown()["verified"] == 0 and empty()
    view = human(dict(mode="rearm_view"))["view"]
    assert human(dict(mode="rearm_confirm", view=view, password=password))["ok"]
    replay = rpc(
        "request",
        dict(schema_version="1.0", operation="propose", body=request),
        actor=identity.name,
    )
    assert replay["ok"] is False
    assert empty() and unknown_path.read_bytes() == unknown_bytes

    # Explicit CI administrator recovery, NOT product/model auto-repair. Use only
    # the same signed sl archive, then purge this no-conffile fixture package.
    assert hashlib.sha256(cached[0].read_bytes()).hexdigest() == change["archive_sha256"]
    repair = command("/usr/bin/dpkg", "--install", str(cached[0]))
    purge = command("/usr/bin/dpkg", "--purge", "sl")
    after = command(
        "/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${db:Status-Status} ${Version}\n"
    ).stdout
    assert before == after
    retired = terminal(("retire-checkpoint", attempt["intent"]["recovery_id"]), RETIRE)
    assert retired["snapshot_deleted"] is False
    clean = recovery.create()
    ack = terminal(("acknowledge-attempt", action, clean["recovery_id"]), ACK)
    assert ack["effects_reversed_verified"] is False
    terminal(("retire-checkpoint", clean["recovery_id"]), RETIRE)
    assert unknown_path.read_bytes() == unknown_bytes
    command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
    assert snapshot().latched and empty()
    return dict(
        action_id=action,
        task_id=task["task_id"],
        request=request,
        request_sha256=request_sha,
        full_plan=plan,
        actual_dpkg=observed,
        frozen_package_pids=sorted(package_pids),
        native_stop_pid=stop_pid,
        broker_and_launcher_stayed_frozen=True,
        root_domain_drained=True,
        package_pidfds_dead=True,
        controller_reply_lost_on_stop=True,
        restart_unknown_no_replay=True,
        unknown_record_sha256=hashlib.sha256(unknown_bytes).hexdigest(),
        unknown_record_preserved=True,
        operator_acknowledgement=ack,
        manual_ci_admin_repair=True,
        product_automatic_repair=False,
        repair_stdout_sha256=hashlib.sha256((repair.stdout + purge.stdout).encode()).hexdigest(),
        package_database_versions_restored=True,
        all_payload_effects_reversed_verified=False,
        physical_input_provenance=None,
        final_generation=snapshot().generation,
    )
