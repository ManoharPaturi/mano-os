import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker.control import dispatch_control
from mano_broker.ipc import Peer, dispatch
from mano_broker.protocol import canonical
from mano_broker.state import Denied, State
from mano_prompt.submit import Submission, prompt_packet, status_packet


class HumanPromptQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.body = dict(human_uid=1002, request_key='a' * 32,
                         prompt='$(touch /etc/policy); this is literal intent')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def call(self, operation, body, uid=0):
        packet = canonical(dict(schema_version='1.0', operation=operation, body=body)).encode()
        return dispatch_control(self.state, packet, peer=Peer(42, uid, uid), now=10, boot_id='boot')

    def test_root_forwarded_intent_is_idempotent_and_never_issues_grant_or_action(self):
        first = self.call('submit_prompt', self.body)
        self.assertEqual(first, self.call('submit_prompt', self.body))
        self.assertEqual(first['prompt']['state'], 'received')
        self.assertIsNone(first['prompt']['task_id'])
        query = dict(prompt_id=first['prompt']['id'], human_uid=1002)
        self.assertEqual(self.call('prompt_status', query), first)
        with self.assertRaises(Denied):
            self.call('prompt_status', query | {'human_uid': 1004})
        with self.assertRaises(Denied):
            self.call('submit_prompt', self.body | {'prompt': 'changed intent'})
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 0)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM grants').fetchone()[0], 0)
        self.assertEqual(self.state.db.execute('SELECT prompt FROM human_prompts').fetchone()[0],
                         self.body['prompt'])

    def test_public_and_nonroot_control_cannot_forge_human_intent(self):
        for uid in (1001, 1002, 1003, 1004):
            with self.assertRaises(Denied):
                self.call('submit_prompt', self.body, uid)
        packet = canonical(dict(schema_version='1.0', operation='submit_prompt',
                                body=self.body)).encode()
        with self.assertRaises(Denied):
            dispatch(self.state, packet, peer=Peer(42, 1004, 1004), now=10, boot_id='boot')
        count = self.state.db.execute('SELECT count(*) FROM human_prompts').fetchone()[0]
        self.assertEqual(count, 0)

    def test_binary_packets_bound_unicode_bytes_and_do_not_accept_caller_identity(self):
        packet = prompt_packet('hello', 'a' * 32)
        self.assertEqual(packet[:2], b'\x01\x05')
        self.assertEqual(packet[34:36], (5).to_bytes(2, 'big'))
        self.assertEqual(packet[36:], b'hello')
        self.assertEqual(status_packet('b' * 32), b'\x01\x06' + b'b' * 32)
        for prompt in ('', 'bad\0input', 'é' * 4097):
            with self.assertRaises(ValueError):
                prompt_packet(prompt, 'a' * 32)

    def test_discovery_is_root_only_scoped_read_only_and_stop_gated(self):
        first = self.call('submit_prompt', self.body)['prompt']
        second = self.call('submit_prompt', self.body | {'request_key': 'b' * 32})['prompt']
        self.call('submit_prompt', self.body | {'human_uid': 1003})
        self.state.db.execute('INSERT INTO human_prompts VALUES(?,?,?,?,?,?,NULL)',
            ('c' * 32, 1002, 'c' * 32, 'old boot', 'old', 'received'))
        query = dict(human_uid=1002)
        expected = dict(schema_version='1.0', ok=True, prompts=[first, second])
        self.assertEqual(self.call('pending_prompts', query), expected)
        self.assertEqual(self.call('pending_prompts', query), expected)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM tasks').fetchone()[0], 0)
        for uid in (1001, 1002, 1003, 1004):
            with self.assertRaises(Denied):
                self.call('pending_prompts', query, uid)
        for extra in (dict(limit=1), dict(boot_id='old'), dict(prompt='replacement')):
            with self.assertRaises(Denied):
                self.call('pending_prompts', query | extra)
        with self.assertRaises(ValueError):
            self.call('pending_prompts', dict(human_uid=True))
        self.call('claim_prompt', dict(human_uid=1002, prompt_id=first['id']))
        self.assertEqual(self.call('pending_prompts', query)['prompts'], [second])
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.call('pending_prompts', query)

    def test_ui_retry_preserves_key_until_acknowledged_then_allows_new_intent(self):
        submission = Submission()
        receipt = dict(id='b' * 32, state='received', task_id=None)
        with patch('mano_prompt.submit.rpc', side_effect=[TimeoutError(),
                dict(ok=True, prompt=receipt), dict(ok=True, prompt=receipt)]) as rpc:
            with self.assertRaises(TimeoutError):
                submission.submit('goal')
            first = rpc.call_args.args[0]
            self.assertEqual(submission.submit('goal'), receipt)
            self.assertEqual(rpc.call_args.args[0], first)
            submission.submit('goal')
            self.assertNotEqual(rpc.call_args.args[0], first)
