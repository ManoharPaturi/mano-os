import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mano_broker.ipc import Peer, dispatch
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State
from mano_broker.terminal_output import chunk, persist, read
from mano_core.broker import read_terminal_output, terminal_output
from mano_protocol.terminal_output import STREAM_LIMIT


class TerminalOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve() / 'journal'
        self.state = State(self.directory)
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
            resource_id='a' * 32, classification='internal', boot_id='boot')
        args = dict(argv=['true'], cwd='.', timeout_seconds=1)
        grant = self.state.issue_grant(self.task, approved_human_uid=1002, approved_args=args,
            capability='terminal.run', resource_id='a' * 32, expires=100, max_count=1,
            memory_bytes=64 * 1024**2, pids=8, cpu_percent=10, max_timeout_seconds=1)
        request = ActionRequest.parse(canonical(dict(schema_version='1.0', task_id=self.task,
            grant_id=grant, capability='terminal.run', resource_id='a' * 32, args=args,
            idempotency_key='run', reason='test')).encode())
        action, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id='boot')
        self.action = action['id']
        self.query = dict(task_id=self.task, action_id=self.action)
        self.identity = dict(caller_uid=1004, boot_id='boot')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def save(self, stdout=b'', stderr=b'', code=0, reason='completed'):
        self.state.start(self.action, now=10, boot_id='boot')
        persist(self.state, self.action, dict(return_code=code, reason=reason),
                dict(stdout=stdout, stderr=stderr), boot_id='boot')

    def client(self, packet):
        return dispatch(self.state, canonical(packet).encode(),
                        peer=Peer(42, 1004, 1004), now=10, boot_id='boot')

    def test_missing_custody_is_not_an_empty_success_and_never_reexecutes(self):
        self.assertIsNone(terminal_output(self.client, **self.query))
        with self.assertRaises(ValueError):
            read_terminal_output(self.client, **self.query)
        self.assertEqual(self.state.db.execute('SELECT state FROM actions').fetchone()[0], 'intent')

    def test_binary_multichunk_empty_and_failed_output_survive_reopen(self):
        out, err = b'\x00\xff' * (STREAM_LIMIT // 2), b'AssertionError\n'
        self.save(out, err, code=1)
        self.state.close()
        self.state = State(self.directory)
        with patch('mano_core.broker.time.sleep') as sleep:
            captured = read_terminal_output(self.client, **self.query)
        self.assertEqual(captured['stdout'], out)
        self.assertEqual(captured['stderr'], err)
        self.assertEqual(captured['metadata']['return_code'], 1)
        self.assertFalse(captured['metadata']['effect_verified'])
        self.assertEqual(sleep.call_count, 16)
        self.assertEqual(captured['metadata']['streams']['stdout']['sha256'],
                         hashlib.sha256(out).hexdigest())

    def test_empty_result_is_available_and_output_limit_is_explicit(self):
        self.save(code=-9, reason='output-limit')
        result = read_terminal_output(self.client, **self.query)
        self.assertEqual(result['stdout'], b'')
        self.assertEqual(result['stderr'], b'')
        self.assertTrue(result['metadata']['output_limit_reached'])
        self.assertEqual(result['metadata']['reason'], 'output-limit')

    def test_scope_range_and_database_corruption_fail_closed(self):
        self.save(b'output', b'error')
        for change in (dict(caller_uid=1005), dict(boot_id='other'), dict(task_id='a' * 32)):
            with self.subTest(change=change), self.assertRaises(Denied):
                read(self.state, **(self.query | self.identity | change))
        for change in (dict(offset=True), dict(offset=999), dict(length=4097),
                       dict(stream='other')):
            with self.assertRaises(Denied):
                chunk(self.state, **(self.query | self.identity | dict(
                    stream='stdout', offset=0, length=4096) | change))
        self.state.db.execute('UPDATE terminal_outputs SET stdout=?', (b'corrupt',))
        with self.assertRaises(Denied):
            read(self.state, **self.query, **self.identity)

    def test_saved_history_after_stop_same_boot_without_new_authority(self):
        self.save(b'saved')
        self.state.emergency_stop()
        self.assertEqual(read_terminal_output(self.client, **self.query)['stdout'], b'saved')

    def test_sdk_denies_changed_chunks_and_does_not_retry_transport_loss(self):
        self.save(b'x' * 5000)
        for changed in (dict(data=''), dict(eof=True), dict(data='not-base64')):
            def client(packet, changed=changed):
                reply = self.client(packet)
                return reply | changed if packet['operation'] == 'terminal_output_read' else reply
            with self.assertRaises(ValueError):
                read_terminal_output(client, **self.query)
        client = Mock(side_effect=TimeoutError())
        with self.assertRaises(TimeoutError):
            read_terminal_output(client, **self.query)
        client.assert_called_once()

    def test_sdk_denies_forged_outcome_scope_size_and_verification(self):
        self.save(b'output')
        for change in (dict(task_id='b' * 32), dict(action_id='b' * 32),
                       dict(effect_verified=True), dict(return_code=True),
                       dict(reason='invented'), dict(output_limit_reached=True),
                       dict(streams=dict(stdout=dict(size=STREAM_LIMIT + 1, sha256='0' * 64),
                                         stderr=dict(size=0, sha256='0' * 64)))):
            def client(packet, change=change):
                reply = self.client(packet)
                reply['output'] = reply['output'] | change
                return reply
            with self.subTest(change=change), self.assertRaises(ValueError):
                terminal_output(client, **self.query)
