"""Old-boot source recovery through installed SDK/PAM, disposable stock guest only.

Root creates and independently observes the nonsecret fixture. Root never performs
the restore or edits the broker journal. No grants/passwords enter evidence.
"""

import hashlib
import os
import pwd
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

from ci_tty import native_terminal

FILES = {
    "before-reboot": (b"stock-ok", False),
    "nested/binary": (b"\x00\xff\x01poweroff\x00", False),
    "run.sh": (b"#!/bin/sh\necho saved-source\n", True),
}

SDK = """import hashlib,json,sys,time
from mano_core.broker import BrokerClient
from mano_core.workspace_checkpoints import Checkpoint,proposal as checkpoint_proposal
from mano_core.restoration import Restore,proposal as restore_proposal
value=json.load(sys.stdin);transport=BrokerClient()
def client(packet):
 time.sleep(.12)
 return transport(packet)
try:
 mode=value['mode']
 if mode=='checkpoint-proposal':
  result=checkpoint_proposal(task_id=value['task_id'],resource_id=value['resource_id'],
   key=value['key'],reason='Save source for separately approved recovery across real poweroff')
 elif mode=='restore-proposal':
  before=Checkpoint(client,proposal=value['before']['proposal'],action_id=value['before']['action_id'])
  result=restore_proposal(before=before,source_action_id=value['source']['action_id'],
   source_sha256=value['source']['metadata']['sha256'],key=value['key'],
   reason='Restore saved pre-poweroff source with fresh destination consent')
 else:
  worker=(Checkpoint if mode=='checkpoint' else Restore).start(client,
   proposal=value['proposal'],grant_id=value['grant_id'])
  deadline=time.monotonic()+25
  while time.monotonic()<deadline:
   state=worker.status()
   if state['state'] in {'done','failed','unknown'}:break
   time.sleep(.12)
  assert state['state']=='done',state
  if mode=='checkpoint':
   saved=worker.read()
   result=dict(action_id=worker.action_id,metadata=saved['metadata'],
    exported_archive_sha256=hashlib.sha256(saved['data']).hexdigest())
  else:result=dict(action_id=worker.action_id,result=worker.result())
 print(json.dumps(result))
finally:transport.close()
"""


class PoweroffRestore:
    def __init__(self, python, public, query, human):
        assert os.geteuid() == 0
        assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
        self.python, self.raw_public, self.query, self.human = python, public, query, human

    def public(self, operation, body, actor):
        time.sleep(.12)  # Negative probes must not pass merely through rate limiting.
        return self.raw_public(operation, body, actor)

    def sdk(self, managed, **body):
        try:
            return self.python(SDK, body, managed["caller_name"])
        except subprocess.CalledProcessError:
            # Read-only, deliberately narrow diagnostics; never export request/grant
            # JSON, private source bytes, protected approval views or passwords.
            with sqlite3.connect("file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro",
                                 uri=True) as database:
                events = database.execute(
                    "SELECT e.event,e.details_json FROM events e JOIN actions a "
                    "ON e.action_id=a.id WHERE a.task_id=? "
                    "AND e.event IN ('checkpoint-denied','restore-denied') ORDER BY e.sequence",
                    (managed["context"]["task_id"],)).fetchall()
            import json

            Path("/opt/mano-lab/evidence/stock-source-denial.json").write_text(
                json.dumps(dict(mode=body["mode"], events=events), indent=2) + "\n")
            raise

    def approval(self, managed, proposed, password, *, cancel_first=False):
        response = self.public("request_approval", proposed, managed["caller_name"])
        assert response["ok"] is True
        pending = response["approval"]
        assert pending["state"] == "pending" and pending["grant_id"] is None
        assert set(pending) == {"approval_id", "state", "grant_id"}
        view = self.query("view", pending["approval_id"])["view"]
        assert view["human_uid"] == pwd.getpwnam(self.human).pw_uid
        assert view["task_id"] == proposed["task_id"] and view["args"] == proposed["args"]
        assert view["capability"] == proposed["capability"]
        if cancel_first:
            code, output = native_terminal(
                "mano_prompt.approve", (pending["approval_id"],), actor=self.human,
                answers=((b"Approve this exact operation?", "n"),),
            )
            assert code == 0 and b"Approval recorded:" not in output
            still = self.public("approval_status", dict(approval_id=pending["approval_id"]),
                                managed["caller_name"])
            assert still["ok"] and still["approval"] == pending
        code, output = native_terminal(
            "mano_prompt.approve", (pending["approval_id"],), actor=self.human,
            answers=((b"Approve this exact operation?", "y"),
                     (b"OS authentication password:", password)),
        )
        assert code == 0 and b"Approval recorded:" in output
        assert password.encode() not in output
        approved = self.public("approval_status", dict(approval_id=pending["approval_id"]),
                               managed["caller_name"])["approval"]
        assert approved["state"] == "approved" and approved["grant_id"] is not None
        return approved["grant_id"], view

    def checkpoint(self, managed, password, key):
        proposed = self.sdk(managed, mode="checkpoint-proposal", key=key,
                            task_id=managed["context"]["task_id"],
                            resource_id=managed["context"]["resource_id"])
        grant, _ = self.approval(managed, proposed, password)
        saved = self.sdk(managed, mode="checkpoint", proposal=proposed, grant_id=grant)
        assert saved["metadata"]["sha256"] == saved["exported_archive_sha256"]
        return saved | dict(proposal=proposed)

    def before(self, managed, password):
        workspace = Path(managed["workspace"])
        # Nonsecret fixture setup by the test observer, not a product Root writer.
        for name, (data, executable) in FILES.items():
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if executable else 0o644)
        source = self.checkpoint(managed, password, "source-before-real-poweroff")
        assert source["metadata"]["files"] == len(FILES)
        assert source["metadata"]["boot_id"] == self.boot()
        (workspace / "nested/binary").write_bytes(b"changed after immutable capture")
        before = self.checkpoint(managed, password, "changed-before-real-poweroff")
        proposed = self.sdk(managed, mode="restore-proposal", before=before, source=source,
                            key="unused-restore-before-real-poweroff")
        grant, view = self.approval(managed, proposed, password)
        assert view["restore_plan"]["source_boot_id"] == self.boot()
        # Stored only in existing Root-only, fsynced PRIVATE file, never evidence.
        return dict(source=source, proposal=proposed, grant_id=grant,
                    source_caller_uid=pwd.getpwnam(managed["caller_name"]).pw_uid)

    @staticmethod
    def boot():
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def after(self, previous, managed, password):
        saved = previous["source_restore"]
        source = saved["source"]
        old = previous["managed"]
        boot = self.boot()
        assert source["metadata"]["boot_id"] != boot
        destination_uid = pwd.getpwnam(managed["caller_name"]).pw_uid
        assert destination_uid != saved["source_caller_uid"]
        assert managed["context"]["task_id"] != old["context"]["task_id"]
        # Both the old caller and new caller lack public read authority to old data.
        for caller in (old["caller_name"], managed["caller_name"]):
            for operation in ("checkpoint_result", "checkpoint_read"):
                body = dict(task_id=old["context"]["task_id"], action_id=source["action_id"])
                if operation == "checkpoint_read":
                    body.update(offset=0, length=16384)
                denied = self.public(operation, body, caller)
                assert denied["ok"] is False
        replay = self.public("propose", saved["proposal"] | dict(grant_id=saved["grant_id"]),
                             old["caller_name"])
        assert replay["ok"] is False
        with sqlite3.connect("file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro",
                             uri=True) as database:
            row = database.execute("SELECT revoked,used FROM grants WHERE id=?",
                                   (saved["grant_id"],)).fetchone()
            action_count = database.execute("SELECT count(*) FROM actions WHERE grant_id=?",
                                            (saved["grant_id"],)).fetchone()[0]
        assert row == (1, 0) and action_count == 0
        before = self.checkpoint(managed, password, "destination-after-real-poweroff")
        proposed = self.sdk(managed, mode="restore-proposal", before=before, source=source,
                            key="fresh-restore-after-real-poweroff")
        workspace = Path(managed["workspace"])
        initial = self.manifest(workspace)
        grant, view = self.approval(managed, proposed, password, cancel_first=True)
        assert self.manifest(workspace) == initial  # Approval performs no file effect.
        review = view["restore_plan"]
        assert view["boot_id"] == boot and review["source_boot_id"] == source["metadata"]["boot_id"]
        assert review["source_task_id"] == old["context"]["task_id"]
        assert review["source_owned_by_same_human"] is True
        assert review["source_sha256"] == source["metadata"]["sha256"]
        restored = self.sdk(managed, mode="restore", proposal=proposed, grant_id=grant)
        receipt = restored["result"]["receipt"]
        assert restored["result"]["state"] == "done" and receipt["postcondition_verified"] is True
        assert receipt["source_sha256"] == source["metadata"]["sha256"]
        assert receipt["files"] == len(FILES) and receipt["source_bytes"] == sum(
            len(value[0]) for value in FILES.values())
        expected = {name: dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                               executable=executable)
                    for name, (data, executable) in FILES.items()}
        assert self.manifest(workspace) == expected
        directories = {str(path.relative_to(workspace)) for path in workspace.rglob("*")
                       if path.is_dir() and path.name != ".mano-write-staging"}
        assert directories == {"nested"}, directories
        assert (Path(old["workspace"]) / "nested/binary").read_bytes() == (
            b"changed after immutable capture")
        (workspace / "before-reboot").write_bytes(b"post-restore edit must survive replay")
        canary = self.manifest(workspace)
        replay = self.public("propose", proposed | dict(grant_id=grant), managed["caller_name"])
        assert replay["ok"] is True and replay["fresh"] is False
        assert replay["action"]["id"] == restored["action_id"]
        assert self.manifest(workspace) == canary
        return dict(actual_poweroff_restore=True, installed_sdk_native_pam=True,
                    old_boot_direct_reads_denied=True, old_unused_restore_grant_revoked=True,
                    old_grant_replay_denied=True, old_grant_unused=True,
                    fresh_destination_same_human_consent=True, cancelled_approval_no_grant=True,
                    approval_no_filesystem_effect=True, exact_bytes_modes_file_set=True,
                    source_mutation_not_restored=True, completed_replay_preserved_edit=True,
                    source_caller_uid=saved["source_caller_uid"],
                    destination_caller_uid=destination_uid,
                    source=source["metadata"], destination_before=before["metadata"],
                    restore=restored, restored_manifest=expected, restored_directories=["nested"],
                    model_disclosure=False,
                    atomic_filesystem_restore=False, fixture_setup="Root test observer only")

    @staticmethod
    def manifest(workspace):
        result = {}
        for directory, dirs, names in os.walk(workspace):
            dirs[:] = [name for name in dirs if name not in {".git", ".mano-write-staging"}]
            for name in names:
                path = Path(directory) / name
                info = path.lstat()
                assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                data = path.read_bytes()
                result[str(path.relative_to(workspace))] = dict(
                    sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                    executable=bool(info.st_mode & 0o111))
        return result
