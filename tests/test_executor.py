import base64
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_broker.executor import Executor
from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.state import Denied, State


class DurableExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'state')
        self.resource = 'a' * 32
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode=Mode.AUTO,
            resource_id=self.resource, classification='internal', boot_id='boot-a')
        args = dict(argv=['/usr/bin/true'], cwd='.', timeout_seconds=10)
        self.grant = self.state.issue_grant(self.task, approved_human_uid=1002,
            approved_args=args, capability=Capability.RUN, resource_id=self.resource,
            expires=100, max_count=2, memory_bytes=128 * 1024**2, pids=24,
            cpu_percent=20, max_timeout_seconds=10)
        request = ActionRequest.parse(canonical(dict(schema_version='1.0', task_id=self.task,
            resource_id=self.resource, grant_id=self.grant, capability='terminal.run',
            args=args, idempotency_key='once', reason='test')).encode())
        row, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id='boot-a')
        self.action = row['id']
        prepared = SimpleNamespace(closed=False, started=False, resource_id=self.resource,
            descriptors={'cwd': SimpleNamespace(fd=11)})
        resource = SimpleNamespace(task_id=self.task, caller_uid=1004, boot_id='boot-a',
            workspace=SimpleNamespace(fd=10))
        self.registry = Mock()
        self.registry.leases = {self.action: prepared}
        self.registry.resources = {self.resource: resource}
        self.registry.start.side_effect = lambda state, action, **kw: state.start(action, **kw)
        self.client = Mock()
        self.client.exchange.side_effect = self.exchange
        self.executor = Executor(self.state, self.registry, self.client,
                                 boot_id='boot-a', clock=lambda: 10)
        self.handle = dict(instance_id='b' * 32, job_id='c' * 32, action_id=self.action)
        self.prepare_hook = lambda: None
        self.fail_start = False
        self.observed_starts = 0
        self.outputs = dict(stdout=b'', stderr=b'')
        self.output_hook = lambda reply: reply
        self.code = 0

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def status(self):
        return self.state.db.execute('SELECT state FROM actions WHERE id=?',
                                    (self.action,)).fetchone()[0]

    def exchange(self, channel, envelope, descriptors=()):
        operation = envelope['operation']
        if operation == 'read_output':
            body = envelope['body']
            data = self.outputs[body['stream']]
            end = body['offset'] + body['length']
            return self.output_hook(dict(schema_version='1.0', ok=True,
                effect_verified=False, state='finished', **self.handle,
                data=base64.b64encode(data[body['offset']:end]).decode(), eof=end >= len(data)))
        if operation == 'launch_task':
            self.assertEqual(descriptors, (10, 11))
            self.assertEqual(self.status(), 'intent')
            self.prepare_hook()
            return dict(schema_version='1.0', ok=True, state='prepared', **self.handle)
        if operation == 'start':
            self.observed_starts += 1
            self.assertEqual(self.status(), 'executing')
            if self.fail_start:
                raise TimeoutError('response lost after possible effect')
            state = 'running'
        else:
            state = 'finished' if operation == 'status' else 'unknown'
        return dict(schema_version='1.0', ok=True, effect_verified=False, state=state,
                    return_code=self.code, reason="completed",
                    stdout_bytes=len(self.outputs['stdout']),
                    stderr_bytes=len(self.outputs['stderr']),
                    **self.handle)

    def test_start_is_durable_once_and_exit_remains_unverified(self):
        self.executor.launch(self.action)
        with self.assertRaises(Denied):
            self.executor.launch(self.action)
        self.assertEqual(self.status(), 'executing')
        self.assertEqual(self.observed_starts, 1)
        self.executor.poll(self.action)
        row = self.state.db.execute('SELECT * FROM actions WHERE id=?',
                                    (self.action,)).fetchone()
        self.assertEqual(row['state'], 'done')
        self.assertEqual(row['verified'], 0)
        self.registry.release.assert_called_once_with(self.action)

    def test_revocation_during_prepare_never_sends_start(self):
        self.prepare_hook = lambda: self.state.db.execute('UPDATE grants SET revoked=1')
        with self.assertRaises(Denied):
            self.executor.launch(self.action)
        self.assertEqual(self.observed_starts, 0)
        self.assertEqual(self.status(), 'failed')
        self.assertEqual(self.client.exchange.call_args.args[1]['operation'], 'cancel')

    def test_lost_start_response_is_unknown_and_never_retried(self):
        self.fail_start = True
        with self.assertRaises(TimeoutError):
            self.executor.launch(self.action)
        self.assertEqual(self.status(), 'unknown')
        with self.assertRaises(Denied):
            self.executor.launch(self.action)
        self.assertEqual(self.observed_starts, 1)

    def test_stop_after_start_cancels_without_claiming_success(self):
        self.executor.launch(self.action)
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.executor.poll(self.action)
        self.assertEqual(self.status(), 'unknown')
        self.assertEqual(self.client.exchange.call_args.args[1]['operation'], 'cancel')

    def test_lower_budget_is_sent_without_exceeding_approved_limits(self):
        self.state.db.execute('UPDATE grants SET budget_json=?',
            (canonical(dict(memory_bytes=64 * 1024**2, pids=16, cpu_percent=10,
                            max_timeout_seconds=10)),))
        self.executor.launch(self.action)
        call = self.client.exchange.call_args_list[0]
        self.assertEqual(call.args[1]['body']['limits'],
                         dict(memory_bytes=64 * 1024**2, pids=16, cpu_percent=10))
        self.assertEqual(self.status(), 'executing')

    def test_failed_command_multichunk_output_is_atomic_and_immutable(self):
        from mano_broker.terminal_output import read

        self.code = 1
        self.outputs = dict(stdout=b'\x00x' * 3000, stderr=b'AssertionError: actual failure')
        self.executor.launch(self.action)
        self.executor.poll(self.action)
        self.assertEqual(self.status(), 'executing')
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM terminal_outputs').fetchone()[0], 0)
        while self.action in self.executor.jobs:
            self.executor.poll(self.action)
        self.assertEqual(self.status(), 'failed')
        meta, row = read(self.state, task_id=self.task, action_id=self.action,
                         caller_uid=1004, boot_id='boot-a')
        self.assertEqual(row['stdout'], self.outputs['stdout'])
        self.assertEqual(row['stderr'], self.outputs['stderr'])
        self.assertEqual(meta['return_code'], 1)
        self.assertFalse(meta['effect_verified'])
        self.assertFalse(self.executor.captures)
        self.assertEqual(self.observed_starts, 1)

    def test_output_loss_is_unknown_without_partial_result_or_retry(self):
        self.outputs['stdout'] = b'x' * 6000
        self.executor.launch(self.action)
        self.executor.poll(self.action)
        self.output_hook = Mock(side_effect=TimeoutError('lost output'))
        with self.assertRaises(TimeoutError):
            self.executor.poll(self.action)
        self.assertEqual(self.status(), 'unknown')
        self.assertFalse(self.executor.captures)
        self.assertFalse(self.executor.jobs)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM terminal_outputs').fetchone()[0], 0)
        self.assertEqual(self.observed_starts, 1)

    def test_stop_during_final_capture_cannot_publish_output(self):
        self.outputs['stdout'] = b'small'
        self.executor.observe_stop = self.state.emergency_stop
        self.executor.launch(self.action)
        with self.assertRaises(Denied):
            self.executor.poll(self.action)
        self.assertEqual(self.status(), 'unknown')
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM terminal_outputs').fetchone()[0], 0)

    def test_changed_handle_or_short_chunk_is_denied(self):
        self.outputs['stdout'] = b'expected'
        self.executor.launch(self.action)
        self.output_hook = lambda reply: reply | dict(action_id='d' * 32)
        with self.assertRaises(Denied):
            self.executor.poll(self.action)
        self.assertEqual(self.status(), 'unknown')

    def test_result_storage_failure_rolls_back_final_state(self):
        import sqlite3

        self.state.db.execute("CREATE TRIGGER reject_output BEFORE INSERT ON terminal_outputs "
                              "BEGIN SELECT RAISE(ABORT,'storage failure'); END")
        self.executor.launch(self.action)
        with self.assertRaises(sqlite3.IntegrityError):
            self.executor.poll(self.action)
        self.assertEqual(self.status(), 'unknown')
        self.assertFalse(self.executor.captures)

    def test_full_result_quota_denies_before_any_launcher_effect(self):
        with patch('mano_broker.executor.capacity', side_effect=Denied('full')):
            with self.assertRaises(Denied):
                self.executor.launch(self.action)
        self.client.exchange.assert_not_called()
        self.assertEqual(self.status(), 'failed')
