import base64
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.pty_jobs import PTYJobs
from mano_broker.state import Denied, State


class PTYJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / "state")
        self.resource = "a" * 32
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode=Mode.AUTO,
            resource_id=self.resource,
            classification="internal",
            boot_id="boot",
        )
        self.args = dict(
            argv=["/bin/cat"], cwd=".", timeout_seconds=30, rows=24, columns=80, input_limit_bytes=8
        )
        self.grant = self.state.issue_grant(
            self.task,
            approved_human_uid=1002,
            approved_args=self.args,
            capability=Capability.PTY,
            resource_id=self.resource,
            expires=100,
            max_count=1,
            memory_bytes=128 * 1024**2,
            pids=24,
            cpu_percent=20,
            max_timeout_seconds=30,
        )
        request = ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id=self.task,
                    resource_id=self.resource,
                    grant_id=self.grant,
                    capability=Capability.PTY,
                    args=self.args,
                    idempotency_key="open",
                    reason="test",
                )
            ).encode()
        )
        row, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id="boot")
        self.action = row["id"]
        self.registry = Mock()
        self.registry.leases = {
            self.action: SimpleNamespace(
                closed=False,
                started=False,
                resource_id=self.resource,
                descriptors={"cwd": SimpleNamespace(fd=11)},
            )
        }
        self.registry.resources = {
            self.resource: SimpleNamespace(
                task_id=self.task, caller_uid=1004, boot_id="boot", workspace=SimpleNamespace(fd=10)
            )
        }
        self.registry.start.side_effect = lambda state, action, **kw: state.start(action, **kw)
        self.client = Mock()
        self.client.exchange.side_effect = self.exchange
        self.jobs = PTYJobs(
            self.state, self.registry, self.client, boot_id="boot", clock=lambda: 10
        )
        self.handle = dict(instance_id="b" * 32, job_id="c" * 32, action_id=self.action)
        self.writes = 0
        self.lost = False
        self.reply_hook = lambda value: value
        self.jobs.launch(self.action)
        self.body = dict(task_id=self.task, action_id=self.action)

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def exchange(self, channel, envelope, descriptors=()):
        operation, body = envelope["operation"], envelope["body"]
        result = dict(
            schema_version="1.0", ok=True, effect_verified=False, state="running", **self.handle
        )
        if channel == "prepare":
            self.assertEqual(descriptors, (10, 11))
            result["state"] = "prepared"
        elif operation == "start":
            self.assertEqual(
                self.state.db.execute("SELECT state FROM actions").fetchone()[0], "executing"
            )
        elif operation == "pty_input":
            self.assertEqual(
                self.state.db.execute(
                    "SELECT state FROM pty_operations WHERE operation_id=?", (body["operation_id"],)
                ).fetchone()[0],
                "intent",
            )
            self.writes += 1
            if self.lost:
                raise TimeoutError("lost after possible write")
            result.update(operation_id=body["operation_id"], written=2)
            return self.reply_hook(result)
        elif operation == "pty_read":
            result.update(
                offset=body["offset"], total_bytes=3, data=base64.b64encode(b"abc").decode()
            )
        return result

    def write(self, key="once", data=b"abc", **changes):
        return self.jobs.dispatch(
            "pty_write",
            self.body | dict(key=key, data=base64.b64encode(data).decode()) | changes,
            caller_uid=1004,
        )

    def test_partial_ack_and_replay_never_send_again(self):
        first = self.write()
        self.assertEqual(first["operation"]["written"], 2)
        self.assertEqual(self.write(), first)
        self.assertEqual(self.writes, 1)
        self.assertEqual(
            self.state.db.execute("SELECT input_bytes FROM pty_sessions").fetchone()[0], 3
        )
        with self.assertRaises(Denied):
            self.write(data=b"abd")
        self.assertEqual(self.writes, 1)

    def test_lost_ack_stays_unknown_and_is_not_retried(self):
        self.lost = True
        with self.assertRaises(TimeoutError):
            self.write()
        self.assertEqual(self.write()["operation"]["state"], "unknown")
        self.assertEqual(self.writes, 1)
        self.assertFalse(self.jobs.jobs)
        self.assertEqual(
            self.state.db.execute("SELECT state FROM actions").fetchone()[0], "unknown"
        )
        self.assertEqual(
            self.state.db.execute("SELECT input_bytes FROM pty_sessions").fetchone()[0], 3
        )

    def test_scope_expiry_stop_and_new_boot_deny_new_input(self):
        for change in (dict(task_id="0" * 32), dict(action_id="0" * 32)):
            with self.assertRaises(Denied):
                self.write(**change)
        with self.assertRaises(Denied):
            self.jobs.dispatch("pty_status", self.body, caller_uid=1005)
        self.jobs.boot_id = "other-boot"
        with self.assertRaises(Denied):
            self.write()
        self.jobs.boot_id = "boot"
        self.jobs.clock = lambda: 101
        with self.assertRaises(Denied):
            self.write()
        self.jobs.clock = lambda: 10
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.write()
        self.assertEqual(self.writes, 0)

    def test_byte_budget_charges_whole_attempt_and_denies_before_effect(self):
        self.write(data=b"abcde")
        with self.assertRaises(Denied):
            self.write(key="two", data=b"abcd")
        self.assertEqual(self.writes, 1)
        self.assertEqual(
            self.state.db.execute("SELECT count(*) FROM pty_operations").fetchone()[0], 1
        )

    def test_changed_private_handle_abandons_without_input_replay(self):
        self.reply_hook = lambda value: value | dict(job_id="f" * 32)
        with self.assertRaises(Denied):
            self.write()
        self.assertEqual(self.write()["operation"]["state"], "unknown")
        self.assertEqual(self.writes, 1)

    def test_stop_between_commit_and_effect_sends_no_input(self):
        self.jobs.observe_stop = self.state.emergency_stop
        with self.assertRaises(Denied):
            self.write()
        self.assertEqual(self.writes, 0)
        self.assertEqual(
            self.state.db.execute("SELECT state FROM pty_operations").fetchone()[0], "unknown"
        )

    def test_live_combined_output_is_scoped_and_prefix_hashed(self):
        self.jobs.poll(self.action)
        result = self.jobs.dispatch(
            "pty_read", self.body | dict(offset=0, length=3), caller_uid=1004
        )["session"]
        self.assertEqual(base64.b64decode(result["data"]), b"abc")
        self.assertFalse(result["eof"])
        self.assertFalse(result["effect_verified"])
        with self.assertRaises(Denied):
            self.jobs.dispatch("pty_read", self.body | dict(offset=0, length=True), caller_uid=1004)

    def test_timeout_and_geometry_schema_are_strict(self):
        for changes in (dict(rows=True), dict(columns=401), dict(input_limit_bytes=65537)):
            with self.assertRaises(ValueError):
                self.state.issue_grant(
                    self.task,
                    approved_human_uid=1002,
                    approved_args=self.args | changes,
                    capability=Capability.PTY,
                    resource_id=self.resource,
                    expires=100,
                    max_count=1,
                    memory_bytes=128 * 1024**2,
                    pids=24,
                    cpu_percent=20,
                    max_timeout_seconds=30,
                )
        with self.assertRaises(ValueError):
            self.state.issue_grant(
                self.task,
                approved_human_uid=1002,
                approved_args=self.args,
                capability=Capability.PTY,
                resource_id=self.resource,
                expires=100,
                max_count=1,
                memory_bytes=128 * 1024**2,
                pids=24,
                cpu_percent=20,
                max_timeout_seconds=1,
            )

    def test_full_history_durably_fails_new_intent_without_prepare(self):
        for index in range(32):
            action = format(index, '032x')
            self.state.db.execute(
                'INSERT INTO actions(id,task_id,grant_id,request_digest,idempotency_key,'
                'request_json,state) SELECT ?,task_id,grant_id,request_digest,?,request_json,'
                "'intent' FROM actions WHERE id=?", (action, 'quota-' + str(index), self.action))
            if index < 31:
                self.state.db.execute('INSERT INTO pty_sessions(action_id) VALUES(?)', (action,))
        calls = self.client.exchange.call_count
        with self.assertRaises(Denied):
            self.jobs.launch(action)
        self.assertEqual(self.client.exchange.call_count, calls)
        self.assertEqual(self.state.db.execute('SELECT state FROM actions WHERE id=?',
                         (action,)).fetchone()[0], 'failed')
