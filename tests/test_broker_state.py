import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.state import Denied, State


class BrokerStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve() / "broker"
        self.state = State(self.directory)
        self.resource = "a" * 32
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode=Mode.AUTO,
            resource_id=self.resource,
            classification="internal",
            boot_id="boot-a",
        )
        self.grant = self.issue()

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def issue(self, **changes):
        values = dict(
            approved_human_uid=1002,
            approved_args={
                "argv": ["python3", "-c", "print(1)"],
                "cwd": ".",
                "timeout_seconds": 10,
            },
            capability=Capability.RUN,
            resource_id=self.resource,
            expires=100,
            max_count=2,
            memory_bytes=64 * 1024**2,
            pids=16,
            cpu_percent=20,
            max_timeout_seconds=30,
        )
        return self.state.issue_grant(self.task, **(values | changes))

    def request(self, **changes):
        body = {
            "schema_version": "1.0",
            "task_id": self.task,
            "grant_id": self.grant,
            "capability": "terminal.run",
            "resource_id": self.resource,
            "args": {"argv": ["python3", "-c", "print(1)"], "cwd": ".", "timeout_seconds": 10},
            "idempotency_key": "build-1",
            "reason": "verify project",
        }
        return ActionRequest.parse(canonical(body | changes).encode())

    def authorize(self, request=None, **changes):
        return self.state.authorize(
            request or self.request(), **(dict(caller_uid=1004, now=10, boot_id="boot-a") | changes)
        )

    def test_schema_blocks_forged_authority_paths_and_duplicate_keys(self):
        for field, value in (
            ("caller_uid", 1002),
            ("action_id", "b" * 32),
            ("verified", True),
            ("env", {"TOKEN": "x"}),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.request(**{field: value})
        for cwd in ("/etc", "../escape", "a/../b"):
            with self.assertRaises(ValueError):
                self.request(args={"argv": ["true"], "cwd": cwd, "timeout_seconds": 10})
        packet = canonical(self.request().body()).replace(
            '"schema_version":"1.0"', '"schema_version":"1.0","schema_version":"1.0"'
        )
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            ActionRequest.parse(packet.encode())

    def test_identity_scope_expiry_count_and_dispatch_checks(self):
        for changes in ({"caller_uid": 1002}, {"now": 100}, {"boot_id": "boot-b"}):
            with self.assertRaises(Denied):
                self.authorize(**changes)
        with self.assertRaises(Denied):
            self.authorize(self.request(resource_id="b" * 32))
        with self.assertRaises(Denied):
            self.authorize(self.request(capability="files.read", args={"path": "file"}))
        with self.assertRaises(Denied):
            self.authorize(self.request(args={"argv": ["true"], "cwd": ".", "timeout_seconds": 31}))
        action, fresh = self.authorize()
        self.assertTrue(fresh)
        with self.assertRaises(Denied):
            self.state.start(action["id"], now=100, boot_id="boot-a")
        self.authorize(self.request(idempotency_key="build-2"))
        with self.assertRaises(Denied):
            self.authorize(self.request(idempotency_key="build-3"))
        self.assertEqual(
            self.state.db.execute("SELECT used FROM grants WHERE id=?", (self.grant,)).fetchone()[
                0
            ],
            2,
        )

    def test_replay_binding_exit_zero_not_verified_and_unknown_after_restart(self):
        action, _ = self.authorize()
        replay, fresh = self.authorize()
        self.assertFalse(fresh)
        self.assertEqual(replay["id"], action["id"])
        with self.assertRaises(Denied):
            self.authorize(self.request(reason="changed"))
        self.state.start(action["id"], now=11, boot_id="boot-a")
        self.state.transition(action["id"], "done", exit_code=0)
        replay, fresh = self.authorize()
        self.assertFalse(fresh)
        self.assertEqual(replay["verified"], 0)
        second, _ = self.authorize(self.request(idempotency_key="build-2"))
        self.state.start(second["id"], now=12, boot_id="boot-a")
        self.state.close()
        self.state = State(self.directory)
        self.assertEqual(self.state.recover(), 1)
        replay, fresh = self.authorize(self.request(idempotency_key="build-2"))
        self.assertFalse(fresh)
        self.assertEqual(replay["state"], "unknown")
        with self.assertRaises(Denied):
            self.state.start(second["id"], now=13, boot_id="boot-a")

    def test_stop_is_durable_and_prevents_queued_dispatch(self):
        action, _ = self.authorize()
        self.state.emergency_stop()
        self.state.close()
        self.state = State(self.directory)
        with self.assertRaises(Denied):
            self.authorize(self.request(idempotency_key="new"))
        with self.assertRaises(Denied):
            self.state.start(action["id"], now=11, boot_id="boot-a")
        with self.assertRaises(Denied):
            self.issue()
        self.assertEqual(self.state.meta("latched"), 1)

    def test_concurrent_single_use_grant_is_atomic(self):
        grant = self.issue(max_count=1)
        barrier = Barrier(2)

        def consume(index):
            state = State(self.directory)
            request = self.request(grant_id=grant, idempotency_key=f"race-{index}")
            try:
                barrier.wait(timeout=5)
                return state.authorize(request, caller_uid=1004, now=10, boot_id="boot-a")[1]
            except Denied:
                return False
            finally:
                state.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(consume, (1, 2)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(
            self.state.db.execute("SELECT used FROM grants WHERE id=?", (grant,)).fetchone()[0], 1
        )

    def test_full_access_does_not_add_capabilities_or_unapproved_grants(self):
        with self.assertRaises(Denied):
            self.issue(approved_human_uid=1004)
        for capability in ("root.exec", "network.upload", "desktop.human", "credentials.read"):
            with self.assertRaises(ValueError):
                self.request(capability=capability)
        self.assertEqual([m.value for m in Mode], ["supervised", "auto", "full-access"])
        with self.assertRaises(ValueError):
            self.issue(memory_bytes=8 * 1024**3)
        with self.assertRaises(ValueError):
            self.issue(max_count=True)

    def test_verification_is_a_separate_trusted_transition(self):
        action, _ = self.authorize()
        with self.assertRaises(ValueError):
            self.state.record_verification(action["id"], checked_artifacts=[])
        self.state.start(action["id"], now=11, boot_id="boot-a")
        self.state.transition(action["id"], "done", exit_code=0)
        self.state.record_verification(
            action["id"], checked_artifacts=[{"artifact_id": "c" * 32, "sha256": "d" * 64}]
        )
        row, _ = self.authorize()
        self.assertEqual(row["verified"], 1)
        self.assertEqual(len(json.loads(row["evidence_json"])), 1)

    def test_modes_preserve_resource_scope_and_distinct_identities(self):
        for mode in Mode:
            task = self.state.create_task(
                human_uid=1002,
                caller_uid=1004,
                mode=mode,
                resource_id=self.resource,
                classification="internal",
                boot_id="boot-a",
            )
            grant = self.state.issue_grant(
                task,
                approved_human_uid=1002,
                approved_args={
                    "argv": ["python3", "-c", "print(1)"],
                    "cwd": ".",
                    "timeout_seconds": 10,
                },
                capability="terminal.run",
                resource_id=self.resource,
                expires=100,
                max_count=1,
                memory_bytes=64 * 1024**2,
                pids=16,
                cpu_percent=20,
                max_timeout_seconds=30,
            )
            with self.assertRaises(Denied):
                self.authorize(self.request(task_id=task, grant_id=grant, resource_id="b" * 32))
            action, fresh = self.authorize(self.request(task_id=task, grant_id=grant))
            self.assertTrue(fresh)
            self.assertEqual(action["state"], "intent")
        with self.assertRaises(ValueError):
            self.state.create_task(
                human_uid=1002,
                caller_uid=1002,
                mode="auto",
                resource_id=self.resource,
                classification="internal",
                boot_id="boot-a",
            )

    def test_empty_file_data_is_valid_and_unsafe_state_paths_fail(self):
        request = self.request(capability="files.write", args={"path": "empty.txt", "text": ""})
        self.assertEqual(json.loads(request.args_json)["text"], "")
        self.request(args={"argv": ["python3", "-c", ""], "cwd": ".", "timeout_seconds": 10})
        alias = self.directory.parent / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            State(alias)
        unsafe = self.directory.parent / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            State(unsafe)

    def test_exact_terminal_arguments_cannot_change_under_valid_grant(self):
        approved = json.loads(self.request().args_json)
        changes = [
            {"argv": ["python3", "-c", "print(2)"]},
            {"cwd": "other"},
            {"timeout_seconds": 9},
        ]
        for update in changes:
            with self.subTest(update=update), self.assertRaises(Denied):
                self.authorize(self.request(args=approved | update))
        self.assertEqual(
            self.state.db.execute("SELECT used FROM grants WHERE id=?", (self.grant,)).fetchone()[
                0
            ],
            0,
        )
        self.assertTrue(self.authorize()[1])

    def test_exact_write_target_and_content_and_empty_payload(self):
        grant = self.issue(capability="files.write", approved_args={"path": "result", "text": ""})
        for args in ({"path": "other", "text": ""}, {"path": "result", "text": "changed"}):
            with self.assertRaises(Denied):
                self.authorize(self.request(grant_id=grant, capability="files.write", args=args))
        self.assertTrue(
            self.authorize(
                self.request(
                    grant_id=grant, capability="files.write", args={"path": "result", "text": ""}
                )
            )[1]
        )

    def test_invalid_approval_template_denies_before_grant_creation(self):
        count = self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0]
        for args in (
            {"argv": ["true"], "cwd": "../escape", "timeout_seconds": 10},
            {"argv": ["true"], "cwd": ".", "timeout_seconds": 31},
            {"argv": ["true"], "cwd": ".", "timeout_seconds": 10, "env": {"KEY": "x"}},
        ):
            with self.assertRaises(ValueError):
                self.issue(approved_args=args)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], count)

    def test_legacy_journal_upgrade_preserves_history_and_revokes_broad_grants(self):
        running, _ = self.authorize()
        self.state.start(running["id"], now=11, boot_id="boot-a")
        queued, _ = self.authorize(self.request(idempotency_key="queued"))
        self.state.db.execute("ALTER TABLE grants DROP COLUMN approved_args_json")
        self.state.close()
        self.state = State(self.directory)
        rows = {r["id"]: r["state"] for r in self.state.db.execute("SELECT id,state FROM actions")}
        self.assertEqual(rows, {running["id"]: "unknown", queued["id"]: "failed"})
        self.assertEqual(
            self.state.db.execute(
                "SELECT revoked FROM grants WHERE id=?", (self.grant,)
            ).fetchone()[0],
            1,
        )
        with self.assertRaises(Denied):
            self.authorize(self.request(idempotency_key="new"))
        with self.assertRaises(Denied):
            self.state.start(queued["id"], now=12, boot_id="boot-a")
        replay, fresh = self.authorize()
        self.assertFalse(fresh)
        self.assertEqual(replay["state"], "unknown")
        self.assertEqual(
            self.state.db.execute(
                "SELECT count(*) FROM events WHERE event='exact-grant-migration'"
            ).fetchone()[0],
            1,
        )
        self.state.close()
        self.state = State(self.directory)
        self.assertEqual(
            self.state.db.execute(
                "SELECT count(*) FROM events WHERE event='exact-grant-migration'"
            ).fetchone()[0],
            1,
        )
