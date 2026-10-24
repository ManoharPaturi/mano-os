"""Interrupt actual approved dpkg; Root observer/repair in disposable CI only."""

import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

from probe_package_apply import GROUP, ROOT, terminal
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


def repair_fixture(plan, cached, before, original_marks, original_marks_mode, action):
    """Explicit disposable CI administrator repair; never installed or model callable."""
    guard()
    assert empty()
    from mano_broker.package_catalog import EXTENDED, MAX_EXTENDED, read
    from mano_runtime import package_attempts, recovery

    assert 1 <= len(plan["changes"]) <= 2
    assert {"sl"} <= {row["name"] for row in plan["changes"]} <= {"sl", "libncurses6"}
    assert all(
        row["operation"] == "install" and row["installed"] is None for row in plan["changes"]
    )
    assert len(original_marks) <= MAX_EXTENDED and original_marks_mode in {0o600, 0o644}
    # Explicit CI administrator recovery, NOT product/model auto-repair. Use only
    # the same complete signed archive set, then purge only its new fixture packages.
    for path, change in zip(cached, plan["changes"], strict=True):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == change["archive_sha256"]
    repair = command("/usr/bin/dpkg", "--install", *map(str, cached))
    purge = command("/usr/bin/dpkg", "--purge", *(row["name"] for row in reversed(plan["changes"])))
    after = command(
        "/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${db:Status-Status} ${Version}\n"
    ).stdout
    assert before == after
    # Explicit CI administrator repair includes the original package marks, not
    # only versions. Preserve the product's four-catalog bound without deleting
    # any history or silently rewriting the Broker's authority journal.
    with recovery.locked():
        stage = EXTENDED.parent / (".mano-ci-restore-marks-" + action)
        fd = os.open(
            stage,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            original_marks_mode,
        )
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), original_marks_mode)
            stream.write(original_marks)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(stage, EXTENDED)
        package_attempts.sync(EXTENDED.parent)
        assert read(EXTENDED, MAX_EXTENDED) == original_marks
    return dict(
        package_database_after=after,
        stdout_sha256=hashlib.sha256((repair.stdout + purge.stdout).encode()).hexdigest(),
        original_marks_sha256=hashlib.sha256(original_marks).hexdigest(),
        restored_marks_sha256=hashlib.sha256(read(EXTENDED, MAX_EXTENDED)).hexdigest(),
    )


def run(rpc, human, identity, password, ready, launcher_pid, stop_client, *, fault="stop"):
    guard()
    assert fault in {"stop", "broker-death", "commit-reply-loss"}
    from mano_broker.package_catalog import EXTENDED, MAX_EXTENDED, read, summary
    from mano_broker.workspaces import create_workspace
    from mano_core.packages import apply_proposal, proposal
    from mano_protocol.actions import ActionRequest, canonical
    from mano_protocol.stop_state import snapshot
    from mano_runtime import package_attempts
    from mano_runtime.package_operator import ACK, RETIRE

    assert snapshot().latched and empty()
    # These independent scenarios deliberately kill/restart the Broker. Do not
    # let preceding CI faults consume the production five-start/60-second budget
    # of this scenario. Wait out that window while Stop is latched, BEFORE any
    # new grant/approval/deadline. Never reset-failed or relax the service limit.
    broker_before_cooldown = ready()
    cooldown = time.monotonic() + 61
    print('CI package fault cooldown: native Stop latched; preserving Broker start limit',
          file=sys.stderr, flush=True)
    while True:
        remaining = cooldown - time.monotonic()
        if remaining <= 0:
            break
        assert snapshot().latched and empty()
        time.sleep(min(1, remaining))
    assert snapshot().latched and empty() and ready() == broker_before_cooldown
    view = human(dict(mode="rearm_view"))["view"]
    assert human(dict(mode="rearm_confirm", view=view, password=password))["ok"]
    generation = snapshot().generation
    # Reuse an already validated current catalog. Do not consume a retained slot
    # just to run another independent scenario over identical package inputs.
    try:
        current_catalog = summary()
        reused_catalog = True
    except ValueError as error:
        if str(error) not in {
            "Installed package state changed; refresh catalog and approval",
            "APT package marks changed; refresh catalog and approval",
        }:
            raise
        command(
            "/usr/bin/env",
            "-i",
            "PATH=/usr/sbin:/usr/bin:/bin",
            "LANG=C.UTF-8",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3",
            "-P",
            "-m",
            "mano_runtime.package_catalog",
        )
        current_catalog = summary()
        reused_catalog = False
    original_marks = read(EXTENDED, MAX_EXTENDED)
    original_marks_mode = EXTENDED.stat().st_mode & 0o777
    assert original_marks_mode in {0o600, 0o644}
    catalog_ids_before = sorted(p.name for p in Path("/var/lib/mano-packages/catalogs").iterdir())
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
        catalog_id=current_catalog["catalog_id"],
        key="actual-dpkg-stop-plan",
        reason="Review signed sl install for disposable interruption test",
    )
    forecast = client(identity, planned, approve(rpc, human, identity, password, planned))
    assert forecast["state"] == "done"
    plan = forecast["result"]["plan"]
    # Exercise the complete real dependency solution, not a pre-seeded library.
    # Test-only administrator recovery permits only fresh sl/libncurses6 installs.
    assert 1 <= len(plan["changes"]) <= 2
    assert {"sl"} <= {row["name"] for row in plan["changes"]} <= {"sl", "libncurses6"}
    cached = []
    for change in plan["changes"]:
        assert change["operation"] == "install" and change["installed"] is None
        matches = [
            p
            for p in Path("/var/cache/apt/archives").glob("*.deb")
            if p.stat().st_size == change["download_bytes"]
            and hashlib.sha256(p.read_bytes()).hexdigest() == change["archive_sha256"]
        ]
        assert len(matches) == 1
        cached.append(matches[0])
    before = command(
        "/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${db:Status-Status} ${Version}\n"
    ).stdout
    before_status = Path("/var/lib/dpkg/status").read_bytes()
    assert hashlib.sha256(before_status).hexdigest() == plan["status_sha256"]
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
    if fault == "commit-reply-loss":
        from probe_package_commit_reply import run as committed_loss

        return committed_loss(
            rpc,
            identity,
            ready,
            launcher_pid,
            stop_client,
            child,
            task=task,
            plan=plan,
            request=request,
            request_sha=request_sha,
            cached=cached,
            before_query=before,
            before_status=before_status,
            original_marks=original_marks,
            original_marks_mode=original_marks_mode,
            generation=generation,
            catalog_ids_before=catalog_ids_before,
        )
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
                    argv = proc.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                    if b"--unpack" not in argv:
                        continue  # A read-only dpkg architecture query is insufficient.
                    fd = os.pidfd_open(pid)
                    descriptors[pid] = fd
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                    wait_stopped(proc)
                    assert proc.joinpath("exe").resolve(strict=True) == Path("/usr/bin/dpkg")
                    assert proc.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0") == argv
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
                        argv=[v.decode() for v in argv],
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
                try:
                    if pid not in descriptors:
                        descriptors[pid] = os.pidfd_open(pid)
                    signal.pidfd_send_signal(descriptors[pid], signal.SIGSTOP)
                    wait_stopped(Path("/proc") / str(pid))
                except (FileNotFoundError, ProcessLookupError):
                    # A short-lived helper can exit before its stop signal. It
                    # must be absent from the final membership, never assumed T.
                    assert pid not in authorities and pid not in members()
        package_pids = members()
        assert observed["pid"] in package_pids and os.getpid() not in package_pids
        for pid in package_pids | set(authorities):
            wait_stopped(Path("/proc") / str(pid))
        if fault == "stop":
            result = command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
            assert "Emergency Stop acknowledged" in result.stdout
        else:
            # Pin-kill only the frozen Broker. BindsTo must drain even a frozen
            # Root controller when its authenticated caller dies, without Stop.
            signal.pidfd_send_signal(descriptors[authorities[0]], signal.SIGKILL)
            wait(lambda: select.select([descriptors[authorities[0]]], [], [], 0)[0])
        wait(empty)
        for pid in package_pids:
            wait(lambda pid=pid: select.select([descriptors[pid]], [], [], 0)[0])
        for pid in authorities if fault == "stop" else authorities[1:]:
            wait_stopped(Path("/proc") / str(pid))
        if fault == "broker-death":
            assert not snapshot().latched and snapshot().generation == generation
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
    if fault == "broker-death":
        ready(previous=authorities[0])
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
    if snapshot().latched:
        view = human(dict(mode="rearm_view"))["view"]
        assert human(dict(mode="rearm_confirm", view=view, password=password))["ok"]
    replay = rpc(
        "request",
        dict(schema_version="1.0", operation="propose", body=request),
        actor=identity.name,
    )
    assert replay["ok"] is False
    assert empty() and unknown_path.read_bytes() == unknown_bytes
    progress = dict(
        phase="before-explicit-ci-admin-repair",
        complete_fixture=False,
        fault=fault,
        action_id=action,
        task_id=task["task_id"],
        request=request,
        full_plan=plan,
        current_catalog_reused=reused_catalog,
        request_sha256=request_sha,
        actual_dpkg=observed,
        frozen_package_pids=sorted(package_pids),
        root_domain_drained=True,
        package_pidfds_dead=True,
        launcher_stayed_frozen=True,
        broker_and_launcher_stayed_frozen=fault == "stop",
        native_stop_not_used_to_drain=fault == "broker-death",
        broker_killed_by_observer=fault == "broker-death",
        restart_unknown_no_replay=True,
        unknown_record=json.loads(unknown_bytes),
        unknown_record_sha256=hashlib.sha256(unknown_bytes).hexdigest(),
        operator_recovery_completed=False,
        product_automatic_repair=False,
    )
    (ROOT / ("evidence/package-apply-" + fault + "-progress.json")).write_text(
        json.dumps(progress, indent=2) + "\n"
    )

    repaired = repair_fixture(plan, cached, before, original_marks, original_marks_mode, action)
    retired = terminal(("retire-checkpoint", attempt["intent"]["recovery_id"]), RETIRE)
    assert retired["snapshot_deleted"] is False
    clean = terminal(("create",))
    ack = terminal(("acknowledge-attempt", action, clean["recovery_id"]), ACK)
    assert ack["effects_reversed_verified"] is False
    terminal(("retire-checkpoint", clean["recovery_id"]), RETIRE)
    assert unknown_path.read_bytes() == unknown_bytes
    command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
    assert snapshot().latched and empty()
    return dict(
        fault=fault,
        action_id=action,
        task_id=task["task_id"],
        request=request,
        request_sha256=request_sha,
        full_plan=plan,
        current_catalog_reused=reused_catalog,
        actual_dpkg=observed,
        frozen_package_pids=sorted(package_pids),
        native_stop_pid=stop_pid,
        broker_and_launcher_stayed_frozen=fault == "stop",
        launcher_stayed_frozen=True,
        native_stop_not_used_to_drain=fault == "broker-death",
        broker_killed_by_observer=fault == "broker-death",
        native_generation_at_apply=generation,
        root_domain_drained=True,
        package_pidfds_dead=True,
        controller_reply_lost_on_stop=fault == "stop",
        controller_reply_lost_on_broker_death=fault == "broker-death",
        restart_unknown_no_replay=True,
        unknown_record_sha256=hashlib.sha256(unknown_bytes).hexdigest(),
        unknown_record_preserved=True,
        unknown_record=json.loads(unknown_bytes),
        intent=attempt["intent"],
        operator_acknowledgement=ack,
        manual_ci_admin_repair=True,
        product_automatic_repair=False,
        repair_stdout_sha256=repaired["stdout_sha256"],
        package_database_versions_restored=True,
        package_marks_restored_by_ci_admin=True,
        original_marks_sha256=repaired["original_marks_sha256"],
        restored_marks_sha256=repaired["restored_marks_sha256"],
        package_database_before=before,
        package_database_after=repaired["package_database_after"],
        all_payload_effects_reversed_verified=False,
        physical_input_provenance=None,
        final_generation=snapshot().generation,
    )
