import json
import unittest
from unittest.mock import patch

from mano_core.cli import main, parse_input
from mano_core.profile import ProfileDenied, verify_current


class CoreCLIGuards(unittest.TestCase):
    def test_strict_input_does_not_accept_authority_fields_duplicate_keys_or_unbounded_data(self):
        value = dict(context=dict(task_id='a' * 32, resource_id='b' * 32,
            operation_key='one', prompt='build'), plan=dict(args={}, reason='test'))
        self.assertEqual(parse_input(json.dumps(value).encode()), value)
        forged_plan = json.dumps(value | {'plan': value['plan'] | {'grant_id': 'c' * 32}}).encode()
        for packet in (b'x' * 65537, b'[]', b'{"context":{},"context":{}}',
                       b'{"context":NaN,"plan":{}}',
                       json.dumps(value | {'caller_uid': 1004}).encode(),
                       forged_plan):
            with self.subTest(packet=packet[:40]), self.assertRaises(ValueError):
                parse_input(packet)

    def test_normal_user_launch_is_denied_before_checkpoint_or_broker_access(self):
        with patch('mano_core.profile.sys.platform', 'darwin'):
            with self.assertRaises(ProfileDenied):
                verify_current()
        with patch('mano_core.cli.verify_current', side_effect=ProfileDenied('Wrong service')), \
             patch('mano_core.cli.BrokerClient') as client, \
             patch('mano_core.cli.Session') as session:
            self.assertEqual(main(['--mock', '--checkpoint-directory', '/unopened']), 1)
            client.assert_not_called()
            session.assert_not_called()

    def test_broker_input_has_only_context_and_fixed_model_metadata(self):
        value = dict(context=dict(task_id='a' * 32, resource_id='b' * 32,
            operation_key='one', prompt='build'),
            model=dict(model='synthetic-snapshot', max_output_tokens=100))
        packet = json.dumps(value).encode()
        self.assertEqual(parse_input(packet, broker_model=True), value)
        for change in ({'api_key': 'forbidden'}, {'endpoint': 'https://elsewhere.invalid'},
                       {'max_output_tokens': True}):
            forged = value | {'model': value['model'] | change}
            with self.assertRaises(ValueError):
                parse_input(json.dumps(forged).encode(), broker_model=True)
        with self.assertRaises(ValueError):
            parse_input(packet)
        with self.assertRaises(ValueError):
            parse_input(json.dumps(value | {'plan': {}}).encode(), broker_model=True)

    def test_broker_cli_constructs_planner_without_direct_provider_or_credentials(self):
        import io
        from types import SimpleNamespace

        from mano_core.planner import BrokerPlanner

        value = dict(context=dict(task_id='a' * 32, resource_id='b' * 32,
            operation_key='one', prompt='build'),
            model=dict(model='synthetic-snapshot', max_output_tokens=100))
        with (
            patch('mano_core.cli.verify_current'),
            patch('mano_core.cli.sys.stdin', SimpleNamespace(
                buffer=io.BytesIO(json.dumps(value).encode()))),
            patch('mano_core.cli.sys.stdout', io.StringIO()) as output,
            patch('mano_core.cli.BrokerClient') as client,
            patch('mano_core.cli.Session') as session,
        ):
            session.return_value.step.return_value = value['context'] | {
                'status': 'awaiting_model_grant'}
            self.assertEqual(main(['--broker-model', '--checkpoint-directory', '/private']), 0)
            planner = session.call_args.args[1]
            self.assertIsInstance(planner, BrokerPlanner)
            self.assertIs(planner.broker, client.return_value)
            self.assertEqual(json.loads(output.getvalue())['task']['status'],
                             'awaiting_model_grant')
            client.return_value.close.assert_called_once()
            session.return_value.close.assert_called_once()
