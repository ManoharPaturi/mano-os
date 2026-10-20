import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.checkpoints import capture
from mano_protocol.checkpoints import MAX_BYTES, archive, path


class GitCheckpointTests(unittest.TestCase):
    def test_native_git_fsck_tree_binary_bytes_and_executable_mode(self):
        executable = shutil.which("git")
        if executable is None:
            self.skipTest("Native Git unavailable")
        files = {
            "a/name.txt": (b"original\n", False),
            "a.b": (b"\0\xffbinary", False),
            "run.sh": (b"#!/bin/sh\necho test\n", True),
            ".gitattributes": (b"* filter=evil diff=evil export-ignore\n", False),
            "unicode-\u03bb": (b"", False),
        }
        data, meta = archive(files)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            repo = root / "repo"
            repo.mkdir()
            with tarfile.open(fileobj=io.BytesIO(data)) as source:
                for member in source:
                    self.assertTrue(member.isfile())
                    self.assertFalse(member.name.startswith("/"))
                    self.assertNotIn("..", Path(member.name).parts)
                    destination = repo / member.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.extractfile(member).read())
            env = dict(
                PATH=os.defpath,
                HOME=folder,
                GIT_CONFIG_NOSYSTEM="1",
                GIT_CONFIG_GLOBAL="/dev/null",
                GIT_TERMINAL_PROMPT="0",
                GIT_ATTR_NOSYSTEM="1",
                LC_ALL="C",
            )

            def git(*args):
                return subprocess.run(
                    [executable, "--git-dir=" + str(repo), *args],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    timeout=5,
                    check=True,
                ).stdout

            git("fsck", "--strict", "--full")
            tree = git("ls-tree", "-rz", "HEAD")
            observed = {}
            for item in tree.rstrip(b"\0").split(b"\0"):
                fields, name = item.split(b"\t", 1)
                mode, kind, oid = fields.split()
                self.assertEqual(kind, b"blob")
                observed[name.decode()] = (git("cat-file", "blob", oid.decode()), mode == b"100755")
            self.assertEqual(observed, files)
            self.assertEqual(git("rev-parse", "HEAD").decode().strip(), meta["commit"])
        self.assertEqual(archive(files)[0], data)
        self.assertEqual(meta["sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse(meta["atomic_filesystem_snapshot"])

    def test_limits_paths_and_file_directory_conflicts(self):
        for name in (
            "../outside",
            "/absolute",
            ".git/config",
            "nested/.git/config",
            ".mano-agent/graph.sqlite",
            ".",
            "double//slash",
            "x/" * 14 + "leaf",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                path(name)
        for files in (
            {"x": (b"a" * (MAX_BYTES + 1), False)},
            {"x": (b"", False), "x/child": (b"", False)},
            {"x": (b"", True), "x/y": (b"", False)},
            {str(n): (b"", False) for n in range(65)},
        ):
            with self.assertRaises(ValueError):
                archive(files)
        self.assertEqual(archive({})[1]["files"], 0)

    def test_capture_walk_excludes_git_state_and_rejects_links_mutation_and_quota(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".git").mkdir()
            (root / ".git/config").write_text("[include]\npath=/host-secret\n")
            (root / ".mano-agent").mkdir(mode=0o700)
            (root / ".mano-agent/graph.sqlite").write_bytes(b"private graph canary")
            (root / "file").write_bytes(b"captured")
            (root / "sub").mkdir()
            (root / "sub/bin").write_bytes(b"\0\xff")

            class Pin:
                def __init__(self, name):
                    self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)

                def close(self):
                    os.close(self.fd)

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    self.close()

            class Workspace:
                def pin(self, name, **_):
                    if ".mano-agent" in Path(name).parts:
                        raise AssertionError("Private runtime state must never be opened")
                    return Pin(root / name)

            # Only replace the Linux immutable-read primitive; real directory,
            # inode/namespace mutation and walking semantics are exercised here.
            handles = []

            def seal(pin, *, maximum):
                source = os.dup(pin.fd)
                handles.append(source)
                size = os.fstat(source).st_size
                if size > maximum:
                    os.close(source)
                    from mano_broker.state import Denied

                    raise Denied("quota")
                return source, dict(size=size)

            with patch("mano_broker.checkpoints.seal", side_effect=seal):
                layout = {}
                result, meta = capture(Workspace(), observe=lambda: None, layout=layout)
                self.assertEqual(layout['excluded'], ['.git', '.mano-agent'])
                self.assertIn('.mano-agent', meta['excluded_names'])
                self.assertEqual(meta["files"], 2)
                self.assertNotIn(b"/host-secret", result)
                self.assertEqual(meta["source_bytes"], 10)
                (root / "link").symlink_to(root / "file")
                with self.assertRaises(ValueError):
                    capture(Workspace(), observe=lambda: None)
                (root / "link").unlink()
                changed = False
                before_handles = len(handles)

                def observe():
                    nonlocal changed
                    if not changed and len(handles) > before_handles:
                        (root / "file").write_bytes(b"changed-after-capture")
                        changed = True

                with self.assertRaises(ValueError):
                    capture(Workspace(), observe=observe)
                for n in range(140):
                    (root / f"file-{n}").touch()
                with self.assertRaises(ValueError):
                    capture(Workspace(), observe=lambda: None)

    def test_sdk_wrong_proposal_and_unknown_never_trigger_recapture(self):
        from unittest.mock import Mock

        from mano_core.workspace_checkpoints import Checkpoint, proposal

        value = proposal(task_id="a" * 32, resource_id="b" * 32, key="once", reason="Checkpoint")
        client = Mock(
            return_value=dict(
                schema_version="1.0",
                ok=True,
                action=dict(
                    id="c" * 32,
                    task_id="a" * 32,
                    verified=0,
                    state="unknown",
                    proposal_digest=hashlib.sha256(
                        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                ),
            )
        )
        worker = Checkpoint(client, proposal=value, action_id="c" * 32)
        with self.assertRaises(ValueError):
            worker.read()
        self.assertEqual(client.call_count, 1)
        client.reset_mock()
        client.return_value = dict(schema_version="1.0", ok=False)
        with self.assertRaises(ValueError):
            Checkpoint.start(client, proposal=value, grant_id="d" * 32)
        self.assertEqual(client.call_count, 1)


class CheckpointCustodyTests(unittest.TestCase):
    def setUp(self):
        from mano_broker.registry import Prepared
        from mano_broker.state import State
        from mano_core.workspace_checkpoints import proposal
        from mano_protocol.actions import ActionRequest, canonical

        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / "state")
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id="a" * 32,
            classification="internal",
            boot_id="boot",
        )
        self.proposal = proposal(task_id=self.task, resource_id="a" * 32, key="once", reason="Save")
        grant = self.state.issue_grant(
            self.task,
            approved_human_uid=1002,
            approved_args=self.proposal["args"],
            capability="workspace.checkpoint",
            resource_id="a" * 32,
            expires=100,
            max_count=1,
            memory_bytes=128 * 1024**2,
            pids=16,
            cpu_percent=20,
            max_timeout_seconds=5,
        )
        self.request = ActionRequest.parse(canonical(self.proposal | dict(grant_id=grant)).encode())
        row, _ = self.state.authorize(self.request, caller_uid=1004, now=10, boot_id="boot")
        self.action = row["id"]
        self.prepared = Prepared(self.action, "a" * 32)
        self.prepared.descriptors = {
            "root": SimpleNamespace(close=lambda: None, fd=10, device=1, inode=2)
        }
        self.resource = SimpleNamespace(
            task_id=self.task,
            caller_uid=1004,
            boot_id="boot",
            human_uid=1002,
            workspace=SimpleNamespace(device=1, inode=2),
        )
        from unittest.mock import Mock

        self.registry = Mock()
        self.registry.leases = {self.action: self.prepared}
        self.registry.resources = {"a" * 32: self.resource}
        self.registry.start.side_effect = lambda state, action, **kw: state.start(action, **kw)
        self.runtime = SimpleNamespace(
            state=self.state, registry=self.registry, boot_id="boot", sync_stop=lambda: None
        )
        self.capture = archive({"original": (b"saved bytes", False)})

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def test_durable_capture_scope_retrieval_reopen_and_idempotent_replay(self):
        from mano_broker.checkpoints import execute, read
        from mano_broker.state import Denied

        with patch("mano_broker.checkpoints.capture", return_value=self.capture):
            execute(self.runtime, self.action, clock=lambda: 10)
        meta, data = read(
            self.state, task_id=self.task, action_id=self.action, caller_uid=1004, boot_id="boot"
        )
        self.assertEqual(data, self.capture[0])
        self.assertEqual(meta["files"], 1)
        for change in (dict(caller_uid=1005), dict(boot_id="other"), dict(task_id="b" * 32)):
            args = (
                dict(task_id=self.task, action_id=self.action, caller_uid=1004, boot_id="boot")
                | change
            )
            with self.assertRaises(Denied):
                read(self.state, **args)
        row, fresh = self.state.authorize(self.request, caller_uid=1004, now=10, boot_id="boot")
        self.assertFalse(fresh)
        self.assertEqual(row["state"], "done")
        self.registry.start.assert_called_once()
        self.registry.release.assert_called_once_with(self.action)
        self.state.db.execute(
            "UPDATE checkpoints SET data=? WHERE action_id=?", (b"corrupt", self.action)
        )
        with self.assertRaises(Denied):
            read(
                self.state,
                task_id=self.task,
                action_id=self.action,
                caller_uid=1004,
                boot_id="boot",
            )

    def test_stop_between_capture_and_commit_never_publishes_or_recaptures(self):
        from mano_broker.checkpoints import execute
        from mano_broker.state import Denied

        def stopped(*args, **kwargs):
            self.state.emergency_stop()
            return self.capture

        with patch("mano_broker.checkpoints.capture", side_effect=stopped):
            with self.assertRaises(Denied):
                execute(self.runtime, self.action, clock=lambda: 10)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM checkpoints").fetchone()[0], 0)
        self.assertEqual(
            self.state.db.execute(
                "SELECT state FROM actions WHERE id=?", (self.action,)
            ).fetchone()[0],
            "unknown",
        )
        row, fresh = self.state.authorize(self.request, caller_uid=1004, now=10, boot_id="boot")
        self.assertFalse(fresh)
        self.assertEqual(row["state"], "unknown")

    def test_low_disk_never_starts_capture(self):
        from mano_broker.checkpoints import execute
        from mano_broker.state import Denied

        with (
            patch(
                "mano_broker.checkpoints.os.statvfs",
                return_value=SimpleNamespace(f_bavail=1, f_frsize=4096),
            ),
            patch("mano_broker.checkpoints.capture") as capture_call,
        ):
            with self.assertRaises(Denied):
                execute(self.runtime, self.action, clock=lambda: 10)
        capture_call.assert_not_called()
        self.registry.start.assert_not_called()
