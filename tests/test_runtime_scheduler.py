import errno
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_broker.ipc import Peer
from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.runtime import Runtime
from mano_broker.state import Denied, State
from mano_broker.stop_state import Snapshot


class RuntimeSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'state')
        with patch('mano_broker.runtime.Registry') as registry:
            self.runtime = Runtime(
                self.state, boot_id='boot', launcher=Mock(), stop_reader=lambda: False
            )
            self.registry = registry.return_value
        self.runtime.executor = Mock()
        self.runtime.executor.jobs = {}
        self.resource = 'a' * 32
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode=Mode.AUTO,
            resource_id=self.resource, classification='internal', boot_id='boot')
        self.registry.resources = {self.resource: SimpleNamespace(task_id=self.task,
            human_uid=1002, caller_uid=1004, boot_id='boot')}
        args = dict(argv=['/usr/bin/true'], cwd='.', timeout_seconds=10)
        grant = self.state.issue_grant(self.task, approved_human_uid=1002, approved_args=args,
            capability=Capability.RUN, resource_id=self.resource, expires=100, max_count=1,
            memory_bytes=128 * 1024**2, pids=24, cpu_percent=20, max_timeout_seconds=10)
        self.request = ActionRequest.parse(canonical(dict(schema_version='1.0', task_id=self.task,
            resource_id=self.resource, grant_id=grant, capability='terminal.run', args=args,
            idempotency_key='one', reason='test')).encode())

        def prepare(state, request, **kwargs):
            row, fresh = state.authorize(request, **kwargs)
            return row, Mock() if fresh else None
        self.registry.prepare.side_effect = prepare

    def tearDown(self):
        self.runtime.close()
        self.state.close()
        self.temp.cleanup()

    def propose(self):
        return self.runtime.dispatch(canonical(dict(schema_version='1.0', operation='propose',
            body=self.request.body())).encode(), peer=Peer(50, 1004, 1004), now=10)

    def test_fresh_authorized_proposal_schedules_once_after_reply(self):
        result = self.propose()
        self.assertEqual(result['action']['state'], 'intent')
        self.runtime.executor.launch.assert_not_called()
        self.assertFalse(self.propose()['fresh'])
        self.assertEqual(list(self.runtime.pending), [result['action']['id']])
        self.runtime.tick()
        self.runtime.tick()
        self.runtime.executor.launch.assert_called_once_with(result['action']['id'])

    def test_two_active_jobs_defer_pending_without_discarding_it(self):
        result = self.propose()
        self.runtime.executor.jobs = {'b' * 32: {}, 'c' * 32: {}}
        self.runtime.tick()
        self.runtime.executor.launch.assert_not_called()
        self.assertEqual(list(self.runtime.pending), [result['action']['id']])
        self.assertEqual(self.runtime.executor.poll.call_count, 2)

    def test_checkpoint_denial_diagnostics_do_not_record_os_filename_or_message(self):
        result = self.propose()
        self.runtime.pending.clear()
        self.runtime.checkpoint_pending.append(result['action']['id'])
        error = PermissionError(errno.EACCES, 'private canary message', '/private/canary')
        with patch('mano_broker.runtime.execute_checkpoint', side_effect=error):
            self.runtime.tick()
        row = self.state.db.execute(
            "SELECT details_json FROM events WHERE event='checkpoint-denied'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn('canary', row[0])
        details = json.loads(row[0])
        self.assertEqual(details['errno'], errno.EACCES)
        self.assertEqual(details['error_type'], 'PermissionError')
        self.assertIsNone(details['denial'])
        self.assertLessEqual(len(details['stages']), 4)

    def test_uncertain_dispatch_is_not_automatically_rescheduled(self):
        self.propose()
        self.runtime.executor.launch.side_effect = TimeoutError()
        self.runtime.tick()
        self.runtime.tick()
        self.runtime.executor.launch.assert_called_once()
        self.assertFalse(self.runtime.pending)

    def test_native_stop_revokes_and_does_not_automatically_rearm(self):
        result = self.propose()
        epoch = self.state.meta('epoch')
        self.runtime.stop_reader = lambda: True
        self.runtime.sync_stop()
        self.assertEqual(self.state.meta('epoch'), epoch + 1)
        self.assertEqual(self.state.meta('latched'), 1)
        with self.assertRaises(Denied):
            self.propose()
        self.assertEqual(self.state.db.execute('SELECT revoked FROM grants').fetchone()[0], 1)
        action = self.state.db.execute('SELECT state FROM actions WHERE id=?',
                                      (result['action']['id'],)).fetchone()
        self.assertEqual(action[0], 'failed')
        self.runtime.sync_stop()
        self.assertEqual(self.state.meta('epoch'), epoch + 1)
        self.runtime.stop_reader = lambda: False
        self.runtime.sync_stop()
        self.assertEqual(self.state.meta('latched'), 1)

    def test_missing_native_stop_authority_latches_broker(self):
        self.runtime.stop_reader = Mock(side_effect=FileNotFoundError())
        self.runtime.sync_stop()
        self.assertEqual(self.state.meta('latched'), 1)

    def test_rearm_seen_after_frozen_stop_revokes_before_new_authority(self):
        self.runtime.stop_reader = lambda: Snapshot(0, False)
        self.runtime.sync_stop()
        result = self.propose()
        self.runtime.stop_reader = lambda: Snapshot(2, False)
        self.runtime.sync_stop()
        self.assertEqual(self.state.meta('latched'), 0)
        self.assertEqual(self.state.db.execute('SELECT revoked FROM grants').fetchone()[0], 1)
        self.assertEqual(self.state.db.execute('SELECT state FROM actions WHERE id=?',
            (result['action']['id'],)).fetchone()[0], 'failed')
        self.runtime.stop_reader = lambda: Snapshot(1, False)
        self.runtime.sync_stop()
        self.assertEqual(self.state.meta('latched'), 1)
        self.assertEqual(self.state.meta('native_generation'), 2)

    def test_live_pty_sessions_share_terminal_concurrency_budget(self):
        result = self.propose()
        self.runtime.ptys = Mock()
        self.runtime.ptys.jobs = {'d' * 32: {}, 'e' * 32: {}}
        self.runtime.tick()
        self.runtime.executor.launch.assert_not_called()
        self.assertEqual(list(self.runtime.pending), [result['action']['id']])
        self.assertEqual(self.runtime.ptys.poll.call_count, 2)
