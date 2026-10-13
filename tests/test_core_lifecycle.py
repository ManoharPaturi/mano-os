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

    def test_dispatcher_reuses_created_context_and_refuses_uncertain_allocation(self):
        from mano_broker.lifecycle import dispatch_prompt

        prompt = 'a' * 32
        managed = self.managed | {'prompt_id': prompt}
        with patch('mano_broker.lifecycle.os.geteuid', return_value=0), \
             patch('mano_broker.lifecycle.sys.platform', 'linux'), \
             patch('mano_broker.lifecycle.human_uid', return_value=1002), \
             patch('mano_broker.lifecycle.control_request', side_effect=[
                 dict(prompt=dict(id=prompt, state='task_created')),
                 dict(managed=managed)]) as control, \
             patch('mano_broker.lifecycle.create_from_prompt') as create, \
             patch('mano_broker.lifecycle.run_mock_step', return_value={'status': 'verifying'}):
            self.assertEqual(dispatch_prompt(prompt, {})['status'], 'verifying')
            create.assert_not_called()
            self.assertEqual([call.args[0] for call in control.call_args_list],
                             ['prompt_status', 'prompt_context'])
        with patch('mano_broker.lifecycle.os.geteuid', return_value=0), \
             patch('mano_broker.lifecycle.sys.platform', 'linux'), \
             patch('mano_broker.lifecycle.human_uid', return_value=1002), \
             patch('mano_broker.lifecycle.control_request', return_value=dict(
                 prompt=dict(id=prompt, state='unknown_task_creation'))), \
             patch('mano_broker.lifecycle.create_from_prompt') as create:
            with self.assertRaises(ValueError):
                dispatch_prompt(prompt, {})
            create.assert_not_called()
