import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.registry import Prepared
from mano_broker.restoration import Restorer, result, validate
from mano_broker.state import Denied, State
from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.checkpoints import EXCLUDED, archive, unpack
from mano_protocol.restoration import plan


class RestoreFormatTests(unittest.TestCase):
    def test_bounded_canonical_git_decoder_preserves_binary_and_modes(self):
        files = {"a/b": (b"\0\xff", True), "z": (b"text\n", False)}
        data, _ = archive(files)
        self.assertEqual(unpack(data), files)
        self.assertEqual(unpack(archive({})[0]), {})
        for changed in (data[:-1], b"not archive", data + b"extra"):
            with self.assertRaises((ValueError, tarfile.TarError)):
                unpack(changed)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as target:
            info = tarfile.TarInfo("../outside")
            info.size = 1
            target.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(ValueError):
            unpack(buffer.getvalue())

    def test_directory_file_swaps_deletions_and_excluded_git_ancestors(self):
        desired = {"a/b": (b"binary", False), "old-dir": (b"file", True)}
        before = {"a": (b"file", False), "old-dir/leaf": (b"remove", False)}
        value = plan(
            desired,
            before,
            before_layout=dict(directories=["old-dir", "preserve"], excluded=["preserve/.git"]),
        )
        self.assertEqual(value["directories"], ["a", "preserve"])
        self.assertEqual(
            [op["operation"] for op in value["operations"]],
            ["unlink", "unlink", "rmdir", "mkdir", "publish", "publish"],
        )
        with self.assertRaises(ValueError):
            plan(
                {"preserve": (b"bad", False)},
                before,
                before_layout=dict(directories=["old-dir", "preserve"], excluded=["preserve/.git"]),
            )


class RestoreLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.state = State(self.base / "state")
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id="a" * 32,
            classification="internal",
            boot_id="boot",
        )
        self.desired = {
            "a/binary": (b"\0\xffsaved", False),
            "script": (b"executable", True),
            "was-directory": (b"now file", False),
        }
        self.previous = {
            "a": (b"was file", False),
            "obsolete/leaf": (b"remove", False),
            "script": (b"changed", False),
            "was-directory/child": (b"remove", False),
        }
        for name, (data, mode) in self.previous.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o770 if mode else 0o660)
        (self.root / ".git").mkdir()
        (self.root / ".git/config").write_text("unchanged")
        self.before_layout = dict(directories=["obsolete", "was-directory"], excluded=[".git"])
        self.source = self.saved(self.desired, key="source")
        self.before = self.saved(self.previous, key="before", layout_value=self.before_layout)
        args = dict(
            source_action_id=self.source[0],
            source_sha256=self.source[1]["sha256"],
            before_action_id=self.before[0],
            before_sha256=self.before[1]["sha256"],
            before_layout_sha256=hashlib.sha256(canonical(self.before_layout).encode()).hexdigest(),
        )
        self.proposal = dict(
            schema_version="1.0",
            task_id=self.task,
            resource_id="a" * 32,
            capability="workspace.restore",
            args=args,
            idempotency_key="restore",
            reason="Restore source",
        )
        self.approvals = Approvals(self.state)
        pending = self.approvals.request(self.proposal, caller_uid=1004, now=10, boot_id="boot")
        self.pending = pending
        self.assertNotIn("restore_plan", pending)
        self.view = self.approvals.view(pending["approval_id"], human_uid=1002)
        grant = self.approvals.approve(
            pending["approval_id"],
            authenticated_human_uid=1002,
            nonce=self.view["nonce"],
            operation_digest=self.view["operation_digest"],
            now=10,
            boot_id="boot",
        )
        self.request = ActionRequest.parse(canonical(self.proposal | dict(grant_id=grant)).encode())
        row, _ = self.state.authorize(self.request, caller_uid=1004, now=10, boot_id="boot")
        self.action = row["id"]

        class Pin:
            def __init__(self, name):
                self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
                info = os.fstat(self.fd)
                self.device, self.inode = info.st_dev, info.st_ino

            def close(self):
                if self.fd >= 0:
                    os.close(self.fd)
                    self.fd = -1

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()

        root = self.root

        class Workspace:
            def __init__(self):
                self.root = Pin(root)
                self.fd, self.device, self.inode = self.root.fd, self.root.device, self.root.inode

            def pin(self, name, **_):
                return Pin(root / name)

        self.workspace = Workspace()
        prepared = Prepared(self.action, "a" * 32)
        prepared.descriptors = {"root": Pin(root)}
        from unittest.mock import Mock

        registry = Mock()
        registry.leases = {self.action: prepared}
        registry.resources = {
            "a" * 32: SimpleNamespace(
                task_id=self.task,
                caller_uid=1004,
                human_uid=1002,
                boot_id="boot",
                workspace=self.workspace,
            )
        }
        registry.start.side_effect = lambda state, action, **kw: state.start(action, **kw)
        registry.release.side_effect = lambda action: prepared.close()
        self.runtime = SimpleNamespace(
            state=self.state, registry=registry, boot_id="boot", sync_stop=lambda: None
        )
        self.worker = Restorer(self.runtime, clock=lambda: 10)

        class Native:
            def mano_create_restore_stage(self, stage, token, executable):
                return os.open(
                    token,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o770 if executable else 0o660,
                    dir_fd=stage,
                )

            def mano_publish_restore(self, stage, token, parent, leaf):
                os.rename(token, leaf, src_dir_fd=stage, dst_dir_fd=parent)
                return 0

            def mano_restore_mkdir(self, parent, leaf):
                os.mkdir(leaf, dir_fd=parent)
                return os.open(leaf, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)

            def mano_restore_remove(self, parent, leaf, directory):
                if directory:
                    os.rmdir(leaf, dir_fd=parent)
                else:
                    os.unlink(leaf, dir_fd=parent)
                return 0

        self.native = Native()

        def seal(pin, *, maximum):
            fd = os.dup(pin.fd)
            size = os.fstat(fd).st_size
            if size > maximum:
                os.close(fd)
                raise Denied("quota")
            return fd, dict(size=size)

        self.seal_patch = patch("mano_broker.checkpoints.seal", side_effect=seal)
        self.native_patch = patch("mano_broker.resources.library", return_value=self.native)
        self.seal_patch.start()
        self.native_patch.start()

    def saved(self, files, *, key, layout_value=None, task_id=None):
        task_id = task_id or self.task
        task = self.state.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        args = dict(root=".", excluded_names=list(EXCLUDED))
        grant = self.state.issue_grant(
            task_id,
            approved_human_uid=task["human_uid"],
            approved_args=args,
            capability="workspace.checkpoint",
            resource_id=task["resource_id"],
            expires=100,
            max_count=1,
            memory_bytes=128 * 1024**2,
            pids=16,
            cpu_percent=20,
            max_timeout_seconds=60,
        )
        request = ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id=task_id,
                    resource_id=task["resource_id"],
                    grant_id=grant,
                    capability="workspace.checkpoint",
                    args=args,
                    idempotency_key=key,
                    reason="Save",
                )
            ).encode()
        )
        row, _ = self.state.authorize(
            request, caller_uid=task["caller_uid"], now=10, boot_id=task["boot_id"]
        )
        self.state.start(row["id"], now=10, boot_id=task["boot_id"])
        data, meta = archive(files)
        meta.update(task_id=task_id, action_id=row["id"], boot_id=task["boot_id"])
        self.state.db.execute(
            "INSERT INTO checkpoints VALUES(?,?,?)", (row["id"], canonical(meta), data)
        )
        if layout_value is not None:
            self.state.db.execute(
                "INSERT INTO checkpoint_layouts VALUES(?,?)", (row["id"], canonical(layout_value))
            )
        self.state.transition(row["id"], "done", exit_code=0)
        return row["id"], meta

    def tearDown(self):
        for action in list(self.worker.jobs):
            self.worker.fail(action)
        self.native_patch.stop()
        self.seal_patch.stop()
        for prepared in self.runtime.registry.leases.values():
            prepared.close()
        self.workspace.root.close()
        self.state.close()
        self.temp.cleanup()

    def run_job(self):
        self.worker.launch(self.action)
        for _ in range(100):
            if not self.worker.jobs:
                break
            self.worker.poll(self.action)
        self.assertFalse(self.worker.jobs)

    def test_binary_modes_directories_deletions_and_independent_final_capture(self):
        self.assertTrue(self.view["restore_plan"]["destructive"])
        self.run_job()
        for name, (data, executable) in self.desired.items():
            self.assertEqual((self.root / name).read_bytes(), data)
            self.assertEqual(bool((self.root / name).stat().st_mode & 0o111), executable)
        self.assertFalse((self.root / "obsolete").exists())
        self.assertEqual((self.root / ".git/config").read_text(), "unchanged")
        observed = result(
            self.state, task_id=self.task, action_id=self.action, caller_uid=1004, boot_id="boot"
        )
        self.assertTrue(observed["receipt"]["postcondition_verified"])
        self.assertFalse(observed["receipt"]["current_content_verified"])
        self.assertEqual(observed["receipt"]["source_sha256"], self.source[1]["sha256"])
        row, fresh = self.state.authorize(self.request, caller_uid=1004, now=10, boot_id="boot")
        self.assertFalse(fresh)
        self.assertEqual(row["state"], "done")

    def test_changed_before_tree_refuses_all_public_effects(self):
        (self.root / "a").write_bytes(b"new change")
        with self.assertRaises(Denied):
            self.worker.launch(self.action)
        self.assertEqual((self.root / "a").read_bytes(), b"new change")
        self.assertTrue((self.root / "obsolete/leaf").exists())
        self.assertEqual(
            self.state.db.execute(
                "SELECT state FROM actions WHERE id=?", (self.action,)
            ).fetchone()[0],
            "unknown",
        )

    def test_stop_during_staging_leaves_source_and_never_automatically_replays(self):
        self.worker.launch(self.action)
        self.worker.poll(self.action)
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.worker.poll(self.action)
        self.assertEqual((self.root / "a").read_bytes(), b"was file")
        row, fresh = self.state.authorize(self.request, caller_uid=1004, now=10, boot_id="boot")
        self.assertFalse(fresh)
        self.assertEqual(row["state"], "unknown")

    def test_lost_mutation_ack_remains_unknown_with_partial_journal(self):
        self.worker.launch(self.action)
        for _ in range(40):
            if self.worker.jobs[self.action]["phase"] == "publish":
                break
            self.worker.poll(self.action)
        original = self.native.mano_restore_remove

        def lost(*args):
            original(*args)
            raise TimeoutError("lost after possible deletion")

        self.native.mano_restore_remove = lost
        with self.assertRaises(TimeoutError):
            self.worker.poll(self.action)
        observed = result(
            self.state, task_id=self.task, action_id=self.action, caller_uid=1004, boot_id="boot"
        )
        self.assertEqual(observed["state"], "unknown")
        self.assertEqual(observed["steps"][0]["state"], "unknown")
        self.assertIsNone(observed["receipt"])
        self.assertFalse(observed["automatic_retry_authorized"])

    def test_other_human_and_tampered_before_layout_cannot_authorize_restore(self):
        from mano_broker.restoration import load

        with self.assertRaises(Denied):
            load(self.state, self.source[0], self.source[1]["sha256"], human_uid=1003)
        self.state.db.execute(
            "UPDATE checkpoint_layouts SET layout_json=? WHERE action_id=?",
            (canonical(dict(directories=[], excluded=[])), self.before[0]),
        )
        with self.assertRaises(Denied):
            validate(self.state, self.request, caller_uid=1004, boot_id="boot")

    def test_older_boot_source_of_same_human_needs_new_destination_consent(self):
        from mano_broker.checkpoints import read

        old_task = self.state.create_task(
            human_uid=1002,
            caller_uid=1008,
            mode="supervised",
            resource_id="b" * 32,
            classification="sensitive",
            boot_id="older-boot",
        )
        saved = self.saved(self.desired, key="historic", task_id=old_task)
        self.state.db.execute("UPDATE grants SET revoked=1 WHERE task_id=?", (old_task,))
        with self.assertRaises(Denied):
            read(self.state, task_id=old_task, action_id=saved[0], caller_uid=1004, boot_id="boot")
        self.state.transition(self.action, "failed")
        self.runtime.registry.release(self.action)
        proposal = self.proposal | dict(
            idempotency_key="recover-historic",
            args=self.proposal["args"]
            | dict(source_action_id=saved[0], source_sha256=saved[1]["sha256"]),
        )
        pending = self.approvals.request(proposal, caller_uid=1004, now=10, boot_id="boot")
        self.assertNotIn("restore_plan", pending)
        view = self.approvals.view(pending["approval_id"], human_uid=1002)
        self.assertEqual(view["restore_plan"]["source_boot_id"], "older-boot")
        self.assertEqual(view["restore_plan"]["source_classification"], "sensitive")
        grant = self.approvals.approve(
            pending["approval_id"],
            authenticated_human_uid=1002,
            nonce=view["nonce"],
            operation_digest=view["operation_digest"],
            now=10,
            boot_id="boot",
        )
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant)).encode())
        row, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id="boot")
        self.action, self.request = row["id"], request
        prepared = Prepared(self.action, "a" * 32)
        prepared.descriptors = {"root": self.workspace.pin(".", directory=True)}
        self.runtime.registry.leases = {self.action: prepared}
        self.runtime.registry.release.side_effect = lambda action: prepared.close()
        self.run_job()
        observed = result(
            self.state, task_id=self.task, action_id=self.action, caller_uid=1004, boot_id="boot"
        )
        self.assertTrue(observed["receipt"]["postcondition_verified"])
        self.assertEqual(
            self.state.db.execute(
                "SELECT count(*) FROM grants WHERE task_id=? AND revoked=0", (old_task,)
            ).fetchone()[0],
            0,
        )

    def test_threaded_broker_refuses_before_fixed_mode_staging(self):
        with patch("threading.active_count", return_value=2):
            with self.assertRaises(Denied):
                self.worker.launch(self.action)
        self.assertFalse((self.root / ".mano-write-staging").exists())
        self.assertEqual(
            self.state.db.execute("SELECT count(*) FROM restore_attempts").fetchone()[0], 0
        )
        self.assertEqual((self.root / "a").read_bytes(), b"was file")
