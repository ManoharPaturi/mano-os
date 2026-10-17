import unittest
from unittest.mock import patch

from mano_broker.controller import run_cycle
from mano_broker.stop_state import Snapshot


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.prompt = 'a' * 32
        self.claim = dict(prompt_id=self.prompt, prompt_state='received', nonce='b' * 64,
                          model='synthetic', max_output_tokens=100)
        self.managed = dict(prompt_id=self.prompt,
            context=dict(operation_key=self.prompt, task_id='c' * 32))
        patches = {
            'os.geteuid': dict(return_value=0), 'sys.platform': dict(new='linux'),
            'snapshot': dict(return_value=Snapshot(0, False)),
            'human_uid': dict(return_value=1002),
            'create_from_prompt': dict(return_value=self.managed),
            'run_broker_step': dict(return_value={'status': 'awaiting_model_grant'}),
            'control_request': dict(side_effect=lambda operation, body:
                {'cycle': self.claim} if operation == 'claim_core_cycle' else {'ok': True}),
        }
        self.mocks = {}
        for name, options in patches.items():
            context = patch('mano_broker.controller.' + name, **options)
            self.mocks[name] = context.start()
            self.addCleanup(context.stop)

    def run_cycle(self):
        return run_cycle(model='synthetic', max_output_tokens=100)

    def test_one_claim_one_creation_one_step_then_record_pending(self):
        self.assertEqual(self.run_cycle(), dict(prompt_id=self.prompt, task_id='c' * 32,
                                               status='awaiting_model_grant'))
        self.mocks['create_from_prompt'].assert_called_once_with(self.prompt)
        self.mocks['run_broker_step'].assert_called_once_with(self.managed,
            model='synthetic', max_output_tokens=100)
        self.assertEqual(self.mocks['control_request'].call_args.args,
            ('finish_core_cycle', dict(human_uid=1002, prompt_id=self.prompt,
                                      nonce='b' * 64, status='awaiting_model_grant')))

    def test_uncertain_creation_is_not_retried(self):
        self.mocks['create_from_prompt'].side_effect = OSError('lost creation acknowledgement')
        with self.assertRaises(OSError):
            self.run_cycle()
        self.mocks['create_from_prompt'].assert_called_once()
        self.mocks['run_broker_step'].assert_not_called()
        self.assertEqual(self.mocks['control_request'].call_args.args[1]['status'],
                         'controller_uncertain')

    def test_stop_before_allocation_prevents_root_factory(self):
        self.mocks['snapshot'].side_effect = [Snapshot(0, False), Snapshot(1, False)]
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.mocks['create_from_prompt'].assert_not_called()
        self.mocks['run_broker_step'].assert_not_called()

    def test_nonroot_denied_before_broker_or_factory(self):
        self.mocks['os.geteuid'].return_value = 1002
        with self.assertRaises(PermissionError):
            self.run_cycle()
        self.mocks['control_request'].assert_not_called()
        self.mocks['create_from_prompt'].assert_not_called()
