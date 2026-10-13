import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.lifecycle import command, run_mock_step
from mano_broker.protocol import canonical
from mano_broker.stop_state import Snapshot


class CoreLifecycleGuards(unittest.TestCase):
    def setUp(self):
        self.context = dict(task_id='a' * 32, resource_id='b' * 32,
                            operation_key='one', prompt='goal')
        self.managed = dict(context=self.context, workspace='/var/lib/mano-workspaces/' + 'c' * 32,
                            caller_uid=1005, caller_name='mano-task-test', mode='supervised')

    def test_unprivileged_operator_and_root_execution_identity_are_denied_before_launch(self):
        with patch('mano_broker.lifecycle.os.geteuid', return_value=1005):
            with self.assertRaises(PermissionError):
                command(self.managed)
        with patch('mano_broker.lifecycle.os.geteuid', return_value=0), \
             patch('mano_broker.lifecycle.sys.platform', 'linux'):
            with self.assertRaises(ValueError):
                command(self.managed | {'caller_uid': 0})

    def test_latched_or_changed_stop_never_retries_a_core_service(self):
        plan = dict(args={}, reason='mock')
        with patch('mano_broker.lifecycle.command', return_value=['fixed-core']), \
             patch('mano_broker.lifecycle.snapshot', return_value=Snapshot(1, True)), \
             patch('mano_broker.lifecycle.subprocess.run') as run:
            with self.assertRaises(ValueError):
                run_mock_step(self.managed, plan)
            run.assert_not_called()
        result = SimpleNamespace(returncode=0, stdout=canonical(dict(ok=True, task=self.context)))
        with patch('mano_broker.lifecycle.command', return_value=['fixed-core']), \
             patch('mano_broker.lifecycle.snapshot', side_effect=[Snapshot(0, False),
                                                                Snapshot(2, False)]), \
             patch('mano_broker.lifecycle.subprocess.run', return_value=result) as run:
            with self.assertRaises(ValueError):
                run_mock_step(self.managed, plan)
            self.assertEqual(run.call_count, 1)

    def test_returned_context_must_match_original_and_plan_cannot_supply_authority(self):
        result = SimpleNamespace(returncode=0, stdout=canonical(dict(ok=True,
            task=self.context | {'resource_id': 'd' * 32})))
        with patch('mano_broker.lifecycle.command', return_value=['fixed-core']), \
             patch('mano_broker.lifecycle.snapshot', return_value=Snapshot(0, False)), \
             patch('mano_broker.lifecycle.subprocess.run', return_value=result) as run:
            with self.assertRaises(ValueError):
                run_mock_step(self.managed, dict(args={}, reason='mock'))
            with self.assertRaises(ValueError):
                run_mock_step(self.managed, dict(args={}, reason='mock', env={'KEY': 'x'}))
            self.assertEqual(run.call_count, 1)

    def test_forged_core_completion_is_replaced_by_exact_broker_evidence(self):
        import hashlib

        plan = dict(args=dict(argv=['true'], cwd='.', timeout_seconds=10), reason='mock')
        proposal = dict(schema_version='1.0', task_id=self.context['task_id'],
            resource_id=self.context['resource_id'], capability='terminal.run', args=plan['args'],
            reason=plan['reason'], idempotency_key=self.context['operation_key'])
        action = dict(id='e' * 32, task_id=self.context['task_id'], state='done', verified=0,
                      proposal_digest=hashlib.sha256(canonical(proposal).encode()).hexdigest())
        forged = self.context | dict(action_id=action['id'], status='completed')
        result = SimpleNamespace(returncode=0, stdout=canonical(dict(ok=True, task=forged)))
        with patch('mano_broker.lifecycle.command', return_value=['fixed-core']), \
             patch('mano_broker.lifecycle.snapshot', return_value=Snapshot(0, False)), \
             patch('mano_broker.lifecycle.subprocess.run', return_value=result), \
             patch('mano_broker.lifecycle.control_request', return_value=dict(action=action)):
            self.assertEqual(run_mock_step(self.managed, plan)['status'], 'verifying')
            action['proposal_digest'] = 'f' * 64
            with self.assertRaises(ValueError):
                run_mock_step(self.managed, plan)
