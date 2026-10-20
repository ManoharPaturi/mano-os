"""Installed native-PAM restore and frozen-broker Stop witnesses, disposable CI only."""

import contextlib
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import time
from pathlib import Path

CLIENT = """import json,sys,time
from mano_core.broker import BrokerClient
from mano_core.workspace_checkpoints import Checkpoint,proposal as checkpoint_proposal
from mano_core.restoration import Restore,proposal as restore_proposal
value=json.load(sys.stdin);transport=BrokerClient()
def client(packet):
 time.sleep(.12)
 return transport(packet)
try:
 mode=value['mode']
 if mode=='checkpoint':
  worker=Checkpoint.start(client,proposal=value['proposal'],grant_id=value['grant_id'])
 elif mode=='restore-proposal':
  before=Checkpoint(client,proposal=value['before_proposal'],action_id=value['before_action_id'])
  proposed=restore_proposal(before=before,source_action_id=value['source_action_id'],
   source_sha256=value['source_sha256'],key=value['key'],reason='Restore exact saved source tree')
  print(json.dumps(proposed));sys.exit(0)
 else:
  worker=Restore.start(client,proposal=value['proposal'],grant_id=value['grant_id'])
 if value.get('start_only'):
  print(json.dumps(dict(action_id=worker.action_id)));sys.exit(0)
 deadline=time.monotonic()+65
 while time.monotonic()<deadline:
  state=worker.status()
  if state['state'] in {'done','failed','unknown'}:break
  time.sleep(.12)
 if mode=='checkpoint':
  assert state['state']=='done',state
  result=dict(metadata=worker.receipt())
 else:result=worker.result()
 print(json.dumps(dict(action_id=worker.action_id,result=result)))
finally:transport.close()
"""


def client(identity, value, *, timeout=75):
    observed = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            identity.name,
            "--",
            "env",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "python3",
            "-c",
            CLIENT,
        ],
        input=json.dumps(value),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
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
    assert set(pending) == {
        "approval_id",
        "state",
        "grant_id",
    }  # No old source names before consent.
    view = human(dict(mode="view", id=pending["approval_id"]))["view"]
    assert view["args"] == proposed["args"]
    if proposed["capability"] == "workspace.restore":
        assert view["restore_plan"]["destructive"] is True
        assert view["restore_plan"]["source_owned_by_same_human"] is True
    grant = human(dict(mode="confirm", view=view, password=password))
    assert grant["ok"]
    return grant["grant_id"], view


def checkpoint(rpc, human, identity, password, task, *, key):
    from mano_core.workspace_checkpoints import proposal

    proposed = proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        key=key,
        reason="Capture exact before tree for separately approved restoration",
    )
    grant, _ = approve(rpc, human, identity, password, proposed)
    saved = client(identity, dict(mode="checkpoint", proposal=proposed, grant_id=grant))
    return dict(
        proposal=proposed, action_id=saved["action_id"], metadata=saved["result"]["metadata"]
    )


def restore_proposal(identity, before, source, *, key):
    return client(
        identity,
        dict(
            mode="restore-proposal",
            before_proposal=before["proposal"],
            before_action_id=before["action_id"],
            source_action_id=source["action_id"],
            source_sha256=source["metadata"]["sha256"],
            key=key,
        ),
    )


def verify(root, expected):
    observed = {}
    for directory, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in {".git", ".mano-write-staging"}]
        for name in names:
            path = Path(directory) / name
            assert path.is_file() and not path.is_symlink()
            observed[str(path.relative_to(root))] = (
                path.read_bytes(),
                bool(path.stat().st_mode & 0o111),
            )
    assert observed == expected, (observed, expected)


def fingerprint(root):
    rows = []
    for directory, dirs, names in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in {".git", ".mano-write-staging"})
        for name in sorted(names):
            path = Path(directory) / name
            rows.append(
                (
                    str(path.relative_to(root)),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    bool(path.stat().st_mode & 0o111),
                )
            )
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def run(rpc, human, identity, password, task, workspace, saved, files, register_identity):
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    source = dict(action_id=saved["action_id"], metadata=saved["result"]["metadata"])
    expected = {name: (data, name == "run.sh") for name, data in files.items()}
    # Exercise file->directory, directory->executable file, binary publication,
    # ordinary text replacement, obsolete files and empty-directory removal.
    (workspace / "nested/binary").unlink()
    (workspace / "nested").rmdir()
    (workspace / "nested").write_bytes(b"file that must become a directory")
    (workspace / "run.sh").unlink()
    (workspace / "run.sh").mkdir()
    (workspace / "run.sh/obsolete").write_bytes(b"directory that must become executable file")
    (workspace / "extra-empty").mkdir()
    before = checkpoint(rpc, human, identity, password, task, key="restore-stale-before")
    proposed = restore_proposal(identity, before, source, key="restore-stale-refusal")
    grant, _ = approve(rpc, human, identity, password, proposed)
    (workspace / "source.py").write_bytes(b"changed after consent; must not overwrite")
    unchanged = fingerprint(workspace)
    stale = client(identity, dict(mode="restore", proposal=proposed, grant_id=grant))
    assert stale["result"]["state"] == "unknown" and stale["result"]["receipt"] is None
    assert fingerprint(workspace) == unchanged
    before = checkpoint(rpc, human, identity, password, task, key="restore-fresh-before")
    proposed = restore_proposal(identity, before, source, key="restore-exact-source")
    grant, view = approve(rpc, human, identity, password, proposed)
    kinds = {item["operation"] for item in view["restore_plan"]["operations"]}
    assert kinds == {"publish", "unlink", "mkdir", "rmdir"}, kinds
    restored = client(identity, dict(mode="restore", proposal=proposed, grant_id=grant))
    assert restored["result"]["state"] == "done"
    assert restored["result"]["receipt"]["postcondition_verified"] is True
    assert restored["result"]["receipt"]["current_content_verified"] is False
    verify(workspace, expected)
    assert not (workspace / "extra-empty").exists()
    # Completed restore receipts stay historical; replay cannot overwrite new work.
    (workspace / "source.py").write_bytes(b"changed after snapshot\n")
    replay = rpc(
        "request",
        dict(schema_version="1.0", operation="propose", body=proposed | dict(grant_id=grant)),
        actor=identity.name,
    )
    assert replay["ok"] and replay["fresh"] is False
    assert replay["action"]["id"] == restored["action_id"]
    assert (workspace / "source.py").read_bytes() == b"changed after snapshot\n"

    from mano_broker.identities import allocate_identity
    from mano_broker.workspaces import create_workspace

    destination_identity = allocate_identity()
    register_identity(destination_identity.name)
    destination, fd = create_workspace(human_uid=1002, caller_uid=destination_identity.uid)
    os.close(fd)
    destination_task = rpc(
        "provision",
        dict(
            schema_version="1.0",
            operation="provision_task",
            body=dict(
                human_uid=1002,
                caller_uid=destination_identity.uid,
                mode="supervised",
                classification="internal",
            ),
        ),
        actor="root",
        directory=destination,
    )
    assert destination_task["ok"]
    denied = rpc(
        "request",
        dict(
            schema_version="1.0",
            operation="checkpoint_result",
            body=dict(task_id=task["task_id"], action_id=source["action_id"]),
        ),
        actor=destination_identity.name,
    )
    assert denied["ok"] is False
    empty = checkpoint(
        rpc, human, destination_identity, password, destination_task, key="restore-new-task"
    )
    cross_proposal = restore_proposal(
        destination_identity, empty, source, key="restore-cross-task-source"
    )
    cross_grant, cross_view = approve(rpc, human, destination_identity, password, cross_proposal)
    assert cross_view["restore_plan"]["source_task_id"] == task["task_id"]
    copied = client(
        destination_identity, dict(mode="restore", proposal=cross_proposal, grant_id=cross_grant)
    )
    assert copied["result"]["state"] == "done"
    verify(destination, expected)
    assert destination_identity.uid != identity.uid
    report = dict(
        restore=restored,
        stale_before_refusal=stale,
        source_checkpoint=source["metadata"],
        native_pam=True,
        exact_binary_text_modes_and_file_set=True,
        directory_file_swaps=True,
        extra_files_and_empty_dirs_removed=True,
        stale_before_no_public_effects=True,
        replay_canary_preserved=True,
        cross_task_read_denied_before_consent=True,
        cross_task_fresh_consent=True,
        cross_task_different_uid=True,
        source_caller_uid=identity.uid,
        destination_caller_uid=destination_identity.uid,
        cross_task_restore=copied,
        source_task_id=task["task_id"],
        destination_task_id=destination_task["task_id"],
        actual_poweroff_restore=False,
        atomic_filesystem_restore=False,
        model_disclosure=False,
    )
    context = dict(task=task, workspace=workspace, source=source)
    return report, context


def start_for_stop(rpc, human, identity, password, context, broker_pid):
    workspace = context["workspace"]
    for number in range(20):
        (workspace / ("restore-stop-extra-" + str(number))).write_text(
            "delete only with explicit consent"
        )
    before = checkpoint(rpc, human, identity, password, context["task"], key="restore-stop-before")
    proposed = restore_proposal(identity, before, context["source"], key="restore-native-stop")
    grant, _ = approve(rpc, human, identity, password, proposed)
    started = client(
        identity, dict(mode="restore", proposal=proposed, grant_id=grant, start_only=True)
    )
    action = started["action_id"]
    context["stop_request"] = proposed | dict(grant_id=grant)
    database = Path("/var/lib/mano-broker/runtime/state.sqlite3")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with contextlib.closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as db:
            state = db.execute("SELECT state FROM actions WHERE id=?", (action,)).fetchone()[0]
            acknowledged = db.execute(
                "SELECT count(*) FROM restore_steps WHERE action_id=? AND state='done'", (action,)
            ).fetchone()[0]
            attempted = db.execute(
                "SELECT plan_json FROM restore_attempts WHERE action_id=?", (action,)
            ).fetchone()
            if attempted is None:
                if state in {"failed", "unknown", "done"}:
                    raise AssertionError(("Restore has no prepared attempt", state))
                time.sleep(0.02)
                continue
            total = len(json.loads(attempted[0])["operations"])
        if state == "executing" and 0 < acknowledged < total:
            os.kill(broker_pid, signal.SIGSTOP)
            for _ in range(100):
                state_line = next(
                    line
                    for line in Path(f"/proc/{broker_pid}/status").read_text().splitlines()
                    if line.startswith("State:")
                )
                if "T" in state_line:
                    return dict(
                        action_id=action,
                        task_id=context["task"]["task_id"],
                        acknowledged_before_stop=acknowledged,
                        total_steps=total,
                        frozen_workspace_sha256=fingerprint(workspace),
                    )
                time.sleep(0.01)
            raise AssertionError("Broker did not freeze during restore")
        time.sleep(0.02)
    raise AssertionError("Restore did not expose an executing partial step before Stop")


def verify_stopped(rpc, identity, context, witness):
    query = dict(
        schema_version="1.0",
        operation="restore_result",
        body=dict(task_id=witness["task_id"], action_id=witness["action_id"]),
    )
    observed = rpc("request", query, actor=identity.name)
    assert observed["ok"]
    value = observed["restore"]
    assert value["state"] == "unknown" and value["receipt"] is None
    assert value["automatic_retry_authorized"] is False
    assert len(value["steps"]) < value["total_steps"]
    replay = rpc(
        "request",
        dict(schema_version="1.0", operation="propose", body=context["stop_request"]),
        actor=identity.name,
    )
    if replay.get("ok") is True:
        assert replay["fresh"] is False and replay["action"]["id"] == witness["action_id"]
        assert replay["action"]["state"] == "unknown"
    assert fingerprint(context["workspace"]) == witness["frozen_workspace_sha256"]
    return value
