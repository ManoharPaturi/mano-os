import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker.protocol import ActionRequest, canonical
from mano_broker.registry import Registry
from mano_broker.state import Denied, State


@unittest.skipUnless(sys.platform == "linux", "Linux resource descriptors required")
class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "work"
        self.root.mkdir()
        (self.root / "file").write_text("allowed")
        self.registry = Registry()
        fd = os.open(self.root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self.resource = self.registry.register(
                fd, human_uid=1002, caller_uid=1004, boot_id="boot-a"
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
            boot_id="boot-a",
        )

    def tearDown(self):
        self.registry.close()
        self.state.close()
        self.temp.cleanup()

    def request(self, cap="files.read", args=None, key="read"):
        args = args or {"path": "file"}
        grant = self.state.issue_grant(
            self.task,
            approved_human_uid=1002,
            approved_args=args,
            capability=cap,
            resource_id=self.resource,
            expires=100,
            max_count=1,
            memory_bytes=1048576,
            pids=4,
            cpu_percent=10,
            max_timeout_seconds=10,
        )
        return ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id=self.task,
                    grant_id=grant,
                    capability=cap,
                    resource_id=self.resource,
                    args=args,
                    idempotency_key=key,
                    reason="test",
                )
            ).encode()
        )

    def prepare(self, request, **changes):
        return self.registry.prepare(
            self.state, request, **(dict(caller_uid=1004, now=10, boot_id="boot-a") | changes)
        )

    def test_descriptor_identity_replay_one_start_and_stop(self):
        request = self.request()
        row, lease = self.prepare(request)
        inode = lease.descriptors["target"].inode
        (self.root / "file").unlink()
        (self.root / "file").symlink_to("/etc/passwd")
        self.assertEqual(os.fstat(lease.descriptors["target"].fd).st_ino, inode)
        replay, second = self.prepare(request)
        self.assertIsNone(second)
        self.assertEqual(replay["id"], row["id"])
        self.assertIs(self.registry.start(self.state, row["id"], now=11, boot_id="boot-a"), lease)
        with self.assertRaises(Denied):
            self.registry.start(self.state, row["id"], now=11, boot_id="boot-a")
        self.registry.release(row["id"])
        self.assertTrue(lease.closed)
        queued, other = self.prepare(
            self.request(
                "terminal.run", {"argv": ["true"], "cwd": ".", "timeout_seconds": 10}, "run"
            )
        )
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.registry.start(self.state, queued["id"], now=12, boot_id="boot-a")
        self.assertTrue(other.closed)

    def test_wrong_identity_and_lost_registry_do_not_consume_grants(self):
        request = self.request()
        for changes in ({"caller_uid": 1001}, {"boot_id": "boot-b"}):
            with self.assertRaises(Denied):
                self.prepare(request, **changes)
        self.registry.close()
        self.registry = Registry()
        with self.assertRaises(Denied):
            self.prepare(request)
        self.assertEqual(self.state.db.execute("SELECT used FROM grants").fetchone()[0], 0)

    def test_new_write_parent_and_failed_path_are_not_dispatched(self):
        row, lease = self.prepare(
            self.request("files.write", {"path": "new.txt", "text": "data"}, "write")
        )
        self.assertEqual(lease.create_name, "new.txt")
        self.assertEqual(lease.descriptors["parent"].inode, self.root.stat().st_ino)
        self.assertFalse((self.root / "new.txt").exists())
        outside = self.base / "outside"
        outside.write_text("protected")
        (self.root / "link").symlink_to(outside)
        request = self.request(args={"path": "link"}, key="bad")
        with self.assertRaises(OSError):
            self.prepare(request)
        replay, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id="boot-a")
        self.assertEqual(replay["state"], "failed")
        with self.assertRaises(Denied):
            self.registry.start(self.state, replay["id"], now=11, boot_id="boot-a")
        self.assertEqual(outside.read_text(), "protected")

    def test_write_parent_replacement_cannot_select_a_different_target(self):
        sub = self.root / "sub"
        sub.mkdir()
        (sub / "file").write_text("original")
        expected = (sub / "file").stat().st_ino
        request = self.request(
            "files.write", {"path": "sub/file", "text": "approved"}, "parent-race"
        )
        workspace = self.registry.resources[self.resource].workspace
        pin = workspace.pin

        def replace_after_parent(path, **kwargs):
            result = pin(path, **kwargs)
            if path == "sub" and kwargs.get("directory"):
                sub.rename(self.root / "retained")
                sub.mkdir()
                (sub / "file").write_text("replacement")
            return result

        with patch.object(workspace, "pin", side_effect=replace_after_parent):
            _, lease = self.prepare(request)
        self.assertEqual(lease.descriptors["target"].inode, expected)
        self.assertNotEqual(lease.descriptors["target"].inode, (sub / "file").stat().st_ino)

    def test_resource_cannot_be_reused_by_a_second_task(self):
        self.prepare(self.request())
        task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id=self.resource,
            classification="internal",
            boot_id="boot-a",
        )
        grant = self.state.issue_grant(
            task,
            approved_human_uid=1002,
            approved_args={"path": "file"},
            capability="files.read",
            resource_id=self.resource,
            expires=100,
            max_count=1,
            memory_bytes=1048576,
            pids=4,
            cpu_percent=10,
            max_timeout_seconds=10,
        )
        request = ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id=task,
                    grant_id=grant,
                    capability="files.read",
                    resource_id=self.resource,
                    args={"path": "file"},
                    idempotency_key="cross-task",
                    reason="test",
                )
            ).encode()
        )
        with self.assertRaises(Denied):
            self.prepare(request)
        self.assertEqual(
            self.state.db.execute("SELECT used FROM grants WHERE id=?", (grant,)).fetchone()[0], 0
        )
