import getpass
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.control import dispatch_control
from mano_broker.ipc import Peer
from mano_broker.prompts import Prompts
from mano_broker.protocol import canonical
from mano_broker.state import Denied, State
from mano_prompt.approve import approve
from mano_prompt.mode import main, profile_packet, read_profile_status, request_profile
from mano_protocol.profiles import scope

ARGS = dict(mode='auto', duration_seconds=60, max_actions=4, max_timeout_seconds=10)


class HumanProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'broker')
        self.state.db.execute("INSERT INTO meta VALUES('native_generation',1)")
        prompts = Prompts(self.state)
        self.prompt = prompts.submit(human_uid=1002, request_key='a'*32,
                                     prompt='goal', boot_id='boot')['id']
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
            resource_id='b'*32, classification='internal', boot_id='boot')
        prompts.claim(self.prompt, human_uid=1002, boot_id='boot')
        prompts.attach(self.prompt, self.task, human_uid=1002, boot_id='boot')
        self.body = dict(human_uid=1002, prompt_id=self.prompt, request_key='c'*32, args=ARGS)

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def call(self, operation, body, uid=0, now=10):
        packet = canonical(dict(schema_version='1.0', operation=operation, body=body)).encode()
        return dispatch_control(self.state, packet, peer=Peer(1, uid, uid), now=now, boot_id='boot')

    def test_human_request_only_creates_pending_exact_idempotent_challenge(self):
        first = self.call('request_profile', self.body)
        self.assertEqual(first, self.call('request_profile', self.body))
        self.assertEqual(first['task_id'], self.task)
        self.assertEqual(first['approval']['state'], 'pending')
        count = self.state.db.execute('SELECT count(*) FROM task_profiles').fetchone()[0]
        self.assertEqual(count, 0)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM grants').fetchone()[0], 0)
        with self.assertRaises(Denied):
            self.call('request_profile', self.body | dict(args=ARGS | dict(mode='full-access')))
        view = Approvals(self.state).view(first['approval']['approval_id'], human_uid=1002)
        self.assertEqual(view['args'], ARGS)
        self.assertEqual(view['profile_scope'], scope('auto'))

    def test_identity_scope_and_extra_selectors_cannot_be_forged(self):
        for body in (self.body | dict(human_uid=1003), self.body | dict(human_uid=True),
                     self.body | dict(task_id=self.task), self.body | dict(boot_id='old'),
                     self.body | dict(caller_uid=1004)):
            with self.subTest(body=body), self.assertRaises((Denied, ValueError)):
                self.call('request_profile', body)
        for uid in (999, 1002, 1004):
            with self.assertRaises(Denied):
                self.call('request_profile', self.body, uid)
        self.state.db.execute("UPDATE tasks SET boot_id='old' WHERE id=?", (self.task,))
        with self.assertRaises(Denied):
            self.call('request_profile', self.body)

    def test_status_is_read_only_and_reports_revocation_not_historical_approval(self):
        query = dict(human_uid=1002, prompt_id=self.prompt)
        before = self.state.db.total_changes
        result = self.call('permission_status', query)
        self.assertFalse(result['profile']['automatic'])
        self.assertEqual(self.state.db.total_changes, before)
        pending = self.call('request_profile', self.body)['approval']
        queue = Approvals(self.state)
        view = queue.view(pending['approval_id'], human_uid=1002)
        queue.approve(pending['approval_id'], authenticated_human_uid=1002, nonce=view['nonce'],
                      operation_digest=view['operation_digest'], now=11, boot_id='boot')
        before = self.state.db.total_changes
        active = self.call('permission_status', query, now=12)
        self.assertTrue(active['profile']['automatic'])
        self.assertEqual(active['profile']['remaining_actions'], 4)
        self.assertEqual(self.state.db.total_changes, before)
        with patch('mano_prompt.mode.rpc', return_value=active):
            self.assertEqual(read_profile_status(self.prompt), active)
        self.state.recover()
        recovered = self.call('permission_status', query, now=12)
        self.assertFalse(recovered['profile']['automatic'])
        self.assertEqual(recovered['profile']['remaining_actions'], 0)
        with patch('mano_prompt.mode.rpc', return_value=recovered):
            self.assertEqual(read_profile_status(self.prompt), recovered)

    def test_packet_exact_bounds_and_acknowledgement_binding(self):
        wire = profile_packet(self.prompt, 'c'*32, ARGS)
        self.assertEqual(len(wire), 72)
        self.assertEqual(wire[:2], b'\x01\x08')
        self.assertEqual(wire[66:], b'\x01\x00\x3c\x04\x00\x0a')
        result = self.call('request_profile', self.body)
        with patch('mano_prompt.mode.rpc', return_value=result) as rpc:
            self.assertEqual(request_profile(self.prompt, 'c'*32, ARGS), result)
            rpc.assert_called_once_with(wire)
        with patch('mano_prompt.mode.rpc', return_value=result | dict(prompt_id='d'*32)):
            with self.assertRaises(ValueError):
                request_profile(self.prompt, 'c'*32, ARGS)
        with patch('mano_prompt.mode.rpc', side_effect=TimeoutError()) as rpc:
            with self.assertRaises(TimeoutError):
                request_profile(self.prompt, 'c'*32, ARGS)
            self.assertEqual(rpc.call_count, 1)

    def test_cli_pipe_is_denied_before_request_or_password(self):
        with (patch('mano_prompt.mode.sys.argv', ['mode', self.prompt, 'auto']),
              patch('mano_prompt.mode.sys.platform', 'linux'),
              patch('mano_prompt.mode.os.getuid', return_value=1002),
              patch('mano_prompt.mode.os.isatty', return_value=False),
              patch('mano_prompt.mode.rpc') as rpc,
              patch('mano_prompt.mode.approve') as approval,
              patch('mano_prompt.mode.sys.stdout', io.StringIO())):
            self.assertEqual(main(), 1)
            rpc.assert_not_called()
            approval.assert_not_called()

    def test_review_mismatch_cancel_and_no_echo_failure_never_confirm(self):
        view = dict(approval_id='d'*32, human_uid=1002, task_id=self.task,
                    capability='policy.set_profile', args=ARGS, profile_scope=scope('auto'))
        for case in ('mismatch', 'cancel', 'no_echo'):
            with (patch('mano_prompt.approve.os.isatty', return_value=True),
                  patch('mano_prompt.approve.os.getuid', return_value=1002),
                  patch('mano_prompt.approve.rpc', return_value=dict(view=view)) as rpc,
                  patch('builtins.input', return_value='n' if case == 'cancel' else 'y'),
                  patch('mano_prompt.approve.getpass.getpass',
                        side_effect=getpass.GetPassWarning()) as secret,
                  patch('mano_prompt.approve.sys.stdout', io.StringIO())):
                expected = dict(task_id='f'*32 if case == 'mismatch' else self.task)
                if case == 'mismatch':
                    with self.assertRaises(ValueError):
                        approve('d'*32, expected=expected)
                elif case == 'cancel':
                    self.assertFalse(approve('d'*32, expected=expected))
                else:
                    with self.assertRaises(getpass.GetPassWarning):
                        approve('d'*32, expected=expected)
                self.assertEqual(rpc.call_count, 1)
                if case != 'no_echo':
                    secret.assert_not_called()
