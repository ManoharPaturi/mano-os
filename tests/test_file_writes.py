import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_broker.file_writes import execute, result
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.registry import Registry
from mano_broker.resources import library
from mano_broker.state import Denied, State
from mano_core.broker import file_write_result


class WriteReceiptTests(unittest.TestCase):
    def test_receipt_is_scoped_bounded_and_never_current_verification(self):
        meta = dict(
            task_id="a" * 32,
            action_id="b" * 32,
            boot_id="boot",
            relative_path="file",
            publication="created",
            sha256=hashlib.sha256(b"ok").hexdigest(),
            size=2,
            published_device=1,
            published_inode=2,
            effect_verified=False,
            current_content_verified=False,
        )
        query = dict(task_id="a" * 32, action_id="b" * 32, path="file")
        client = Mock(return_value=dict(schema_version="1.0", ok=True, publication=meta))
        self.assertEqual(file_write_result(client, **query), meta)
        for change in (
            dict(task_id="c" * 32),
            dict(current_content_verified=True),
            dict(effect_verified=True),
            dict(publication="inplace"),
            dict(size=32769),
            dict(published_inode=True),
        ):
            client.return_value["publication"] = meta | change
            with self.assertRaises(ValueError):
                file_write_result(client, **query)


@unittest.skipUnless(sys.platform == "linux", "Linux native pinned publication required")
class NativeWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.registry = Registry()
        fd = os.open(self.root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self.resource = self.registry.register(
                fd, human_uid=1002, caller_uid=1004, boot_id="boot"
            )
        finally:
            os.close(fd)
        self.state = State(self.base / "state")
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id=self.resource,
            classification="internal",
            boot_id="boot",
        )
        self.runtime = SimpleNamespace(
            state=self.state, registry=self.registry, boot_id="boot", sync_stop=lambda: None
        )
        self.native = library()

    def tearDown(self):
        self.registry.close()
        self.state.close()
        self.temp.cleanup()

    def prepare(self, path="file", text="approved"):
        args = dict(path=path, text=text)
        grant = self.state.issue_grant(
            self.task,
            approved_human_uid=1002,
            approved_args=args,
            capability="files.write",
            resource_id=self.resource,
            expires=100,
            max_count=1,
            memory_bytes=1048576,
            pids=4,
            cpu_percent=10,
            max_timeout_seconds=10,
        )
        self.request = ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id=self.task,
                    resource_id=self.resource,
                    grant_id=grant,
                    capability="files.write",
                    args=args,
                    idempotency_key="write",
                    reason="test",
                )
            ).encode()
        )
        row, lease = self.registry.prepare(
            self.state, self.request, caller_uid=1004, now=10, boot_id="boot"
        )
        self.action = row["id"]
        return lease

    def run_write(self, hook=None):
        def publish(*args):
            if hook:
                hook()
            return self.native.mano_publish_write(*args)

        proxy = SimpleNamespace(
            mano_create_write_stage=self.native.mano_create_write_stage, mano_publish_write=publish
        )
        with (
            patch(
                "mano_broker.file_writes.pwd.getpwuid",
                return_value=SimpleNamespace(pw_gid=os.getgid()),
            ),
            patch("mano_broker.file_writes.library", return_value=proxy),
        ):
            execute(self.runtime, self.action, clock=lambda: 10)

    def receipt(self, **change):
        return result(
            self.state,
            **(
                dict(task_id=self.task, action_id=self.action, caller_uid=1004, boot_id="boot")
                | change
            ),
        )

    def test_create_replace_empty_and_historical_receipt_without_reexecution(self):
        for initial, text in ((None, "hello\u2603"), ("old", "")):
            with self.subTest(initial=initial):
                if initial is not None:
                    (self.root / "file").write_text(initial)
                self.prepare(text=text)
                self.run_write()
                self.assertEqual((self.root / "file").read_text(), text)
                receipt = self.receipt()
                self.assertEqual(receipt["sha256"], hashlib.sha256(text.encode()).hexdigest())
                self.assertFalse(receipt["effect_verified"])
                (self.root / "file").write_text("changed later")
                row, fresh = self.registry.prepare(
                    self.state, self.request, caller_uid=1004, now=10, boot_id="boot"
                )
                self.assertIsNone(fresh)
                self.assertEqual(row["state"], "done")
                self.assertEqual(self.receipt(), receipt)
                self.assertEqual((self.root / "file").read_text(), "changed later")
                if initial is None:
                    # Fresh independent task for the second scenario's key.
                    self.state.db.execute("UPDATE actions SET idempotency_key='previous'")

    def test_create_race_never_overwrites_new_entry(self):
        self.prepare()
        with self.assertRaises(OSError):
            self.run_write(lambda: (self.root / "file").write_text("raced"))
        self.assertEqual((self.root / "file").read_text(), "raced")
        self.assertIsNone(self.receipt())
        self.assertEqual(
            self.state.db.execute("SELECT state FROM actions").fetchone()[0], "unknown"
        )

    def test_existing_symlink_and_hardlink_races_never_mutate_external_inode(self):
        for link in ("symlink", "hardlink"):
            (self.root / "file").write_text("old")
            outside = self.base / ("outside-" + link)
            outside.write_text("protected")
            self.prepare()

            def swap(link=link, outside=outside):
                (self.root / "file").unlink()
                if link == "symlink":
                    (self.root / "file").symlink_to(outside)
                else:
                    os.link(outside, self.root / "file")

            self.run_write(swap)
            self.assertEqual(outside.read_text(), "protected")
            self.assertEqual((self.root / "file").read_text(), "approved")
            self.state.db.execute(
                "UPDATE actions SET idempotency_key=? WHERE id=?", (link, self.action)
            )

    def test_replaced_parent_name_cannot_redirect_publication(self):
        sub = self.root / "sub"
        sub.mkdir()
        (sub / "file").write_text("old")
        self.prepare(path="sub/file")
        sub.rename(self.root / "retained")
        sub.mkdir()
        (sub / "file").write_text("replacement")
        self.run_write()
        self.assertEqual((self.root / "retained/file").read_text(), "approved")
        self.assertEqual((sub / "file").read_text(), "replacement")

    def test_stop_after_real_publication_preserves_unknown_and_never_retries(self):
        self.prepare()
        count = 0

        def observe():
            nonlocal count
            count += 1
            if count == 3:
                self.state.emergency_stop()

        self.runtime.sync_stop = observe
        with self.assertRaises(Denied):
            self.run_write()
        self.assertEqual((self.root / "file").read_text(), "approved")
        self.assertEqual(
            self.state.db.execute("SELECT state FROM actions").fetchone()[0], "unknown"
        )
        self.assertIsNone(self.receipt())
        self.assertFalse(self.registry.leases)

    def test_foreign_staging_and_reserved_input_deny(self):
        self.prepare()
        (self.root / ".mano-write-staging").symlink_to(self.base)
        with self.assertRaises(OSError):
            self.run_write()
        self.assertFalse((self.root / "file").exists())
        with self.assertRaises(ValueError):
            self.prepare(path=".mano-write-staging/secret")

    def test_scope_and_expiry_stop_deny_before_filesystem_mutation(self):
        self.prepare()
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.run_write()
        self.assertFalse((self.root / "file").exists())
        self.assertFalse((self.root / ".mano-write-staging").exists())
        with self.assertRaises(Denied):
            self.receipt(caller_uid=1005)
