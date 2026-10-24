"""Lose Broker acknowledgement after real commit; disposable Root CI only."""

import hashlib
import json
import os
import select
import signal
import sqlite3
import time
from pathlib import Path

from probe_package_apply import ROOT, terminal
from probe_package_apply_stop import command, empty, members, repair_fixture, wait
from probe_package_plans import guard, wait_stopped


def run(
    rpc,
    identity,
    ready,
    launcher_pid,
    stop_client,
    child,
    *,
    task,
    plan,
    request,
    request_sha,
    cached,
    before_query,
    before_status,
    original_marks,
    original_marks_mode,
    generation,
    catalog_ids_before,
):
    guard()
    from mano_protocol.stop_state import snapshot
    from mano_runtime import package_attempts
    from mano_runtime.package_operator import RETIRE

    stdout, stderr = child.communicate(timeout=8)
    assert child.returncode == 0, stderr[-4096:]
    action = json.loads(stdout)["action_id"]
    directory = package_attempts.BASE / action
    broker_pid = ready()
    authorities = (broker_pid, launcher_pid)
    descriptors = {pid: os.pidfd_open(pid) for pid in authorities}
    controller = None
    observed = None
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if controller is None:
                for pid in members():
                    proc = Path("/proc") / str(pid)
                    try:
                        argv = proc.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                        if argv != [
                            b"/usr/bin/python3",
                            b"-P",
                            b"-m",
                            b"mano_runtime.package_apply",
                        ]:
                            continue
                        assert proc.joinpath("exe").resolve(strict=True) == Path(
                            "/usr/bin/python3"
                        ).resolve(strict=True)
                        assert (
                            proc.joinpath("cgroup")
                            .read_text()
                            .startswith("0::/mano.slice/mano-package.slice/")
                        )
                        fields = dict(
                            line.split(":", 1)
                            for line in proc.joinpath("status").read_text().splitlines()
                        )
                        assert fields["Uid"].split() == ["0"] * 4
                        assert int(fields["CapEff"], 16) & (1 << 21)
                        assert os.readlink(proc / "ns/pid") == os.readlink("/proc/self/ns/pid")
                        descriptors[pid] = os.pidfd_open(pid)
                        controller = pid
                        break
                    except (FileNotFoundError, ProcessLookupError):
                        continue
            if controller is not None:
                try:
                    intent = package_attempts.record(directory / "intent.json")
                    outcome = package_attempts.verified_record(directory / "verified.json", intent)
                    break
                except (FileNotFoundError, json.JSONDecodeError):
                    pass
            time.sleep(0.001)
        else:
            raise AssertionError("No actual completed Root record observed before reply")
        assert outcome["request_sha256"] == intent["request_sha256"] == request_sha
        assert outcome["plan_sha256"] == request["args"]["plan_sha256"]
        for pid in (controller, *authorities):
            signal.pidfd_send_signal(descriptors[pid], signal.SIGSTOP)
            wait_stopped(Path("/proc") / str(pid))
        for _unused in range(4):
            for pid in members():
                try:
                    if pid not in descriptors:
                        descriptors[pid] = os.pidfd_open(pid)
                    signal.pidfd_send_signal(descriptors[pid], signal.SIGSTOP)
                    wait_stopped(Path("/proc") / str(pid))
                except (FileNotFoundError, ProcessLookupError):
                    assert pid != controller and pid not in members()
        package_pids = members()
        assert controller in package_pids and os.getpid() not in package_pids
        for pid in package_pids:
            wait_stopped(Path("/proc") / str(pid))
        with (directory / "verified.json").open("rb") as stream:
            completed_bytes = stream.read(4097)
            assert len(completed_bytes) <= 4096
            os.fsync(stream.fileno())
        package_attempts.sync(directory)
        assert json.loads(completed_bytes) == outcome
        after_status = Path("/var/lib/dpkg/status").read_bytes()
        assert (
            hashlib.sha256(after_status).hexdigest()
            == outcome["postconditions"]["after_status_sha256"]
        )
        # Read-only observation only: never seed, edit or promote Broker history.
        with sqlite3.connect(
            "file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro", uri=True
        ) as database:
            before_broker = database.execute(
                "SELECT state,verified FROM actions WHERE id=?", (action,)
            ).fetchone()
            ack_events = database.execute(
                "SELECT count(*) FROM events WHERE action_id=? "
                "AND event='package-postconditions-verified'",
                (action,),
            ).fetchone()[0]
        assert before_broker == ("executing", 0) and ack_events == 0
        assert (
            sorted(p.name for p in Path("/var/lib/mano-packages/catalogs").iterdir())
            == catalog_ids_before
        ), "Observer missed the pre-publication reply-loss boundary"
        signal.pidfd_send_signal(descriptors[broker_pid], signal.SIGKILL)
        wait(lambda: select.select([descriptors[broker_pid]], [], [], 0)[0])
        wait(empty)
        for pid in package_pids:
            wait(lambda pid=pid: select.select([descriptors[pid]], [], [], 0)[0])
        wait_stopped(Path("/proc") / str(launcher_pid))
        assert not snapshot().latched and snapshot().generation == generation
        observed = dict(
            controller_pid=controller,
            frozen_package_pids=sorted(package_pids),
            broker_before_kill=list(before_broker),
            broker_ack_events_before_kill=ack_events,
            root_domain_drained=True,
            package_pidfds_dead=True,
            launcher_stayed_frozen=True,
            native_stop_not_used_to_drain=True,
            catalog_ids_before=catalog_ids_before,
            catalogs_unchanged_before_kill=True,
        )
    finally:
        for pid in authorities:
            if not select.select([descriptors[pid]], [], [], 0)[0]:
                signal.pidfd_send_signal(descriptors[pid], signal.SIGCONT)
        for fd in descriptors.values():
            os.close(fd)
        if observed is None and not empty():
            command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
    ready(previous=broker_pid)
    query = dict(
        schema_version="1.0",
        operation="status",
        body=dict(task_id=task["task_id"], action_id=action),
    )
    state = rpc("request", query, actor=identity.name)["action"]
    assert state["state"] == "unknown" and state["verified"] == 0
    assert (directory / "verified.json").read_bytes() == completed_bytes
    assert not (directory / "unknown.json").exists()
    rows = package_attempts.reconcile()
    row = next(r for r in rows if r["intent"]["attempt_id"] == action)
    assert row["outcome"] == outcome
    replay = rpc(
        "request",
        dict(schema_version="1.0", operation="propose", body=request),
        actor=identity.name,
    )
    assert replay["ok"] is False and empty()
    proof = dict(
        complete_fixture=False,
        phase="before-explicit-ci-admin-repair",
        action_id=action,
        task_id=task["task_id"],
        request=request,
        request_sha256=request_sha,
        full_plan=plan,
        intent=intent,
        root_outcome=outcome,
        root_verified_record_sha256=hashlib.sha256(completed_bytes).hexdigest(),
        root_verified_record_preserved=True,
        broker_after_restart=state,
        observation=observed,
        no_automatic_replay=True,
        replay_response=replay,
        product_automatic_repair=False,
        physical_input_provenance=None,
        all_payload_effects_reversed_verified=False,
    )
    (ROOT / "evidence/package-commit-reply-loss-progress.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    (ROOT / "evidence/package-commit-reply-before-status").write_bytes(before_status)
    (ROOT / "evidence/package-commit-reply-after-status").write_bytes(after_status)
    repaired = repair_fixture(
        plan, cached, before_query, original_marks, original_marks_mode, action
    )
    retired = terminal(("retire-checkpoint", intent["recovery_id"]), RETIRE)
    assert retired["snapshot_deleted"] is False
    assert (directory / "verified.json").read_bytes() == completed_bytes
    command("/usr/sbin/runuser", "-u", "mano-human", "--", str(stop_client))
    assert snapshot().latched and empty()
    return proof | dict(
        complete_fixture=True,
        phase="complete-after-explicit-ci-admin-repair",
        manual_ci_admin_repair=True,
        repair=repaired,
        metadata_retirement=retired,
        root_record_is_historical_after_repair=True,
        current_installation_verified=False,
        final_generation=snapshot().generation,
    )
