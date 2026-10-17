import os
import socket
import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.ipc import Peer, dispatch
from mano_broker.models import ModelStore
from mano_broker.state import Denied, State
from mano_core.broker import read_model_result
from mano_protocol.actions import ActionRequest, canonical


class ModelOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve() / 'journal'
        self.state = State(self.directory)
        self.state.db.execute("INSERT INTO meta VALUES('native_generation',0)")
        self.store = ModelStore(self.state)
        self.task = self.state.create_task(human_uid=1002, caller_uid=1005, mode='supervised',
            resource_id='a' * 32, classification='sensitive', boot_id='boot')
        self.proposal = dict(schema_version='1.0', task_id=self.task, resource_id='a' * 32,
            capability='model.plan', args=dict(provider='openai', model='snapshot',
                prompt='goal', max_output_tokens=100), idempotency_key='call-one', reason='plan')
        queue = Approvals(self.state)
        pending = queue.request(self.proposal, caller_uid=1005, now=10, boot_id='boot')
        view = queue.view(pending['approval_id'], human_uid=1002)
        grant = queue.approve(pending['approval_id'], authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'], now=11, boot_id='boot')
        request = ActionRequest.parse(canonical(self.proposal | {'grant_id': grant}).encode())
        action, _ = self.state.authorize(request, caller_uid=1005, now=12, boot_id='boot')
        self.action = action['id']
        self.plan = dict(args=dict(argv=['true'], cwd='.', timeout_seconds=1), reason='test')
        self.packet = canonical(dict(object='response', model='snapshot', status='completed',
            usage=dict(input_tokens=2, output_tokens=3, total_tokens=5),
            output=[dict(type='function_call', name='propose_terminal', status='completed',
                         arguments=canonical(self.plan))])).encode()

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def read(self, uid=1005, boot='boot'):
        def client(envelope):
            return dispatch(self.state, canonical(envelope).encode(),
                peer=Peer(42, uid, uid), now=15, boot_id=boot)
        return read_model_result(client, task_id=self.task, action_id=self.action)

    def test_result_is_durable_same_caller_scoped_and_not_task_verification(self):
        self.assertEqual(self.store.begin(self.action, now=12, boot_id='boot'),
                         self.proposal['args'])
        with self.assertRaises(Denied):
            self.store.begin(self.action, now=12, boot_id='boot')
        result = self.store.finish(self.action, self.packet, boot_id='boot')
        self.assertEqual(result['plan'], self.plan)
        self.assertEqual(self.read(), result)
        self.state.close()
        self.state = State(self.directory)
        self.store = ModelStore(self.state)
        self.state.recover()
        self.assertEqual(self.read(), result)
        for uid in (0, 1002, 1006):
            with self.assertRaises(Denied):
                self.read(uid)
        with self.assertRaises(Denied):
            self.read(boot='other')
        row = self.state.db.execute('SELECT state,verified FROM actions').fetchone()
        self.assertEqual(tuple(row), ('done', 0))
        with self.assertRaises(Denied):
            self.store.finish(self.action, self.packet, boot_id='boot')

    def assert_unknown_no_repeat(self, transition):
        self.store.begin(self.action, now=12, boot_id='boot')
        transition()
        for operation in (lambda: self.store.begin(self.action, now=12, boot_id='boot'),
                lambda: self.store.finish(self.action, self.packet, boot_id='boot'), self.read):
            with self.assertRaises(Denied):
                operation()
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM actions').fetchone()[0], 'unknown')

    def test_lost_ack_preserves_unknown_without_repeating_attempt(self):
        self.assert_unknown_no_repeat(lambda: self.store.uncertain(self.action, boot_id='boot'))

    def test_restart_preserves_unknown_without_repeating_attempt(self):
        self.assert_unknown_no_repeat(self.state.recover)

    def test_stop_preserves_unknown_without_repeating_attempt(self):
        self.assert_unknown_no_repeat(self.state.emergency_stop)

    def test_unreserved_malformed_and_corrupt_custody_fail_closed(self):
        with self.assertRaises(Denied):
            self.store.finish(self.action, self.packet, boot_id='boot')
        self.store.begin(self.action, now=12, boot_id='boot')
        with self.assertRaises(ValueError):
            self.store.finish(self.action, b'{"status":"failed"}', boot_id='boot')
        self.assertEqual(self.state.db.execute('SELECT state FROM actions').fetchone()[0],
                         'executing')
        self.store.finish(self.action, self.packet, boot_id='boot')
        self.state.db.execute("UPDATE model_attempts SET result_json='{}'")
        with self.assertRaises(Denied):
            self.read()

    def test_public_callers_cannot_reserve_finish_or_forge_results(self):
        for operation in ('begin_model_attempt', 'finish_model_attempt', 'uncertain_model_attempt'):
            packet = canonical(dict(schema_version='1.0', operation=operation,
                                    body=dict(action_id=self.action))).encode()
            with self.assertRaises(Denied):
                dispatch(self.state, packet, peer=Peer(42, 1005, 1005), now=12, boot_id='boot')
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 0)

    def test_corrupted_task_binding_cannot_disclose_original_plan_to_another_caller(self):
        self.store.begin(self.action, now=12, boot_id='boot')
        self.store.finish(self.action, self.packet, boot_id='boot')
        other = self.state.create_task(human_uid=1003, caller_uid=1006, mode='supervised',
            resource_id='b' * 32, classification='sensitive', boot_id='boot')
        self.state.db.execute('UPDATE actions SET task_id=? WHERE id=?', (other, self.action))
        packet = canonical(dict(schema_version='1.0', operation='model_result',
                                body=dict(task_id=other, action_id=self.action,
                                          offset=0, length=4096))).encode()
        with self.assertRaises(Denied):
            dispatch(self.state, packet, peer=Peer(42, 1006, 1006), now=15, boot_id='boot')

    def test_large_valid_result_is_transferred_in_bounded_chunks(self):
        import json
        self.plan['args']['argv'] = ['true'] + ['x' * 4000] * 16
        response = json.loads(self.packet)
        response['output'][0]['arguments'] = canonical(self.plan)
        response['usage']['input_tokens'] = int('9' * 1200)
        response['usage']['total_tokens'] = response['usage']['input_tokens'] + 3
        self.store.begin(self.action, now=12, boot_id='boot')
        result = self.store.finish(self.action, canonical(response).encode(), boot_id='boot')
        self.assertGreater(len(canonical(result)), 65536)
        self.assertEqual(self.read(), result)
        if hasattr(socket, 'SCM_CREDENTIALS'):
            from mano_protocol.transport import reply

            def wire_client(envelope):
                response = dispatch(self.state, canonical(envelope).encode(),
                    peer=Peer(42, 1005, 1005), now=15, boot_id='boot')
                packet = canonical(response).encode()
                self.assertLess(len(packet), 65536)
                sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with sender, receiver:
                    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                    sender.settimeout(1)
                    receiver.settimeout(1)
                    self.assertEqual(sender.send(packet), len(packet))
                    peer, received = reply(receiver, expected_uid=os.getuid(),
                                           expected_gid=os.getgid())
                    self.assertEqual(peer.pid, os.getpid())
                    return received

            self.assertEqual(read_model_result(wire_client, task_id=self.task,
                                               action_id=self.action), result)
        for offset, length in ((-1, 1), (True, 1), (0, False), (0, 4097), (131073, 1)):
            with self.assertRaises(Denied):
                self.store.chunk(self.action, task_id=self.task, caller_uid=1005,
                    boot_id='boot', offset=offset, length=length)

    def test_client_rejects_changed_digest_and_truncated_transfer(self):
        self.store.begin(self.action, now=12, boot_id='boot')
        self.store.finish(self.action, self.packet, boot_id='boot')
        for field, value in (('eof', False), ('data', 'eA=='),
                             ('result', dict(action_id=self.action, task_id=self.task,
                                             size=1, sha256='0' * 64))):
            def client(envelope, field=field, value=value):
                response = dispatch(self.state, canonical(envelope).encode(),
                    peer=Peer(42, 1005, 1005), now=15, boot_id='boot')
                return response | {field: value}
            with self.assertRaises(ValueError):
                read_model_result(client, task_id=self.task, action_id=self.action)
