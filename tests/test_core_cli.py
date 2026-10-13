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
