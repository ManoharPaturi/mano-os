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

    def test_resume_reuses_original_broker_context_without_task_allocation(self):
        self.claim['prompt_state'] = 'task_created'
        self.mocks['control_request'].side_effect = lambda operation, body: (
            {'cycle': self.claim} if operation == 'claim_core_cycle'
            else {'managed': self.managed} if operation == 'prompt_context' else {'ok': True})
        self.run_cycle()
        self.mocks['create_from_prompt'].assert_not_called()
        self.mocks['run_broker_step'].assert_called_once_with(self.managed,
            model='synthetic', max_output_tokens=100)

    def test_busy_or_empty_claim_does_not_allocate_or_launch(self):
        self.mocks['control_request'].return_value = {'cycle': None}
        self.mocks['control_request'].side_effect = None
        self.assertIsNone(self.run_cycle())
        self.mocks['create_from_prompt'].assert_not_called()
        self.mocks['run_broker_step'].assert_not_called()

    def test_changed_original_prompt_cannot_launch_core(self):
        self.managed['context']['operation_key'] = 'd' * 32
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.mocks['run_broker_step'].assert_not_called()
        self.assertEqual(self.mocks['control_request'].call_args.args[1]['status'],
                         'controller_uncertain')

    def test_cli_reports_subprocess_uncertainty_without_traceback_or_retry(self):
        import io
        import json
        import subprocess

        from mano_broker.controller import main

        with (
            patch('mano_broker.controller.run_cycle',
                  side_effect=subprocess.CalledProcessError(1, ['fixed-helper'])) as cycle,
            patch('mano_broker.controller.sys.stdout', io.StringIO()) as output,
        ):
            self.assertEqual(main(['--model', 'synthetic', '--max-output-tokens', '100']), 1)
            self.assertEqual(json.loads(output.getvalue())['error'], 'uncertain')
            cycle.assert_called_once()
