import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.control import dispatch_control
from mano_broker.human_status import snapshot
from mano_broker.ipc import Peer
from mano_broker.prompts import Prompts
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State
from mano_prompt.intake import Intake
from mano_prompt.task_status import packet, parse_snapshot, read_task_status


class HumanTaskStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'broker')
        self.queue = Approvals(self.state)
        self.prompts = Prompts(self.state)
        self.prompt = self.prompts.submit(human_uid=1002, request_key='a' * 32,
            prompt='sensitive prompt canary', boot_id='boot')['id']
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004,
            mode='supervised', resource_id='b' * 32, classification='sensitive', boot_id='boot')
        self.prompts.claim(self.prompt, human_uid=1002, boot_id='boot')
        self.prompts.attach(self.prompt, self.task, human_uid=1002, boot_id='boot')
        self.proposal = dict(schema_version='1.0', task_id=self.task, capability='files.write',
            resource_id='b' * 32, args=dict(path='result', text='secret payload canary'),
            idempotency_key='action', reason='untrusted explanation canary')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def read(self, **changes):
        return snapshot(self.state, **(dict(human_uid=1002, prompt_id=self.prompt,
                                           boot_id='boot', now=12) | changes))

    def action(self, index):
        proposal = self.proposal | dict(idempotency_key=f'action{index}')
        pending = self.queue.request(proposal, caller_uid=1004, now=10, boot_id='boot')
        view = self.queue.view(pending['approval_id'], human_uid=1002)
        grant = self.queue.approve(pending['approval_id'], authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'], now=11, boot_id='boot')
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant)).encode())
        return self.state.authorize(request, caller_uid=1004, now=12, boot_id='boot')[0]['id']

    def test_read_only_projection_excludes_args_challenges_grants_and_secrets(self):
        pending = self.queue.request(self.proposal, caller_uid=1004, now=10, boot_id='boot')
        action = self.action(1)
        self.state.start(action, now=12, boot_id='boot')
        self.state.transition(action, 'done', exit_code=0)
        before = self.state.db.total_changes
        result = parse_snapshot(self.read(), self.prompt)
        self.assertEqual(self.state.db.total_changes, before)
        self.assertEqual(result['action_count'], 1)
        self.assertEqual(result['actions'][0]['state'], 'done')
        self.assertFalse(result['actions'][0]['effect_verified'])
        self.assertIn(pending['approval_id'], [a['approval_id'] for a in result['approvals']])
        wire = canonical(result)
        for secret in ('nonce', 'grant_id', 'operation_digest', 'secret payload canary',
                       'sensitive prompt canary', 'untrusted explanation canary', 'args'):
            self.assertNotIn(secret, wire)
        self.assertEqual(self.read(now=71)['approvals'][-1]['state'], 'expired')
        self.state.emergency_stop()
        self.assertEqual(self.read()['approvals'][-1]['state'], 'revoked')

    def test_wrong_human_boot_task_binding_and_untrusted_control_denied(self):
        for changes in (dict(human_uid=1003), dict(human_uid=True), dict(boot_id='old')):
            with self.assertRaises((Denied, ValueError)):
                self.read(**changes)
        body = dict(human_uid=1002, prompt_id=self.prompt)
        def call(body, uid=0):
            wire = canonical(dict(schema_version='1.0', operation='human_task_status',
                                  body=body)).encode()
            return dispatch_control(self.state, wire, peer=Peer(1, uid, uid),
                                    now=12, boot_id='boot')
        self.assertEqual(call(body)['snapshot'], self.read())
        for uid in (1002, 1004, 999):
            with self.assertRaises(Denied):
                call(body, uid)
        for extra in (dict(task_id=self.task), dict(limit=999), dict(boot_id='old')):
            with self.assertRaises(Denied):
                call(body | extra)
        self.state.db.execute('UPDATE tasks SET human_uid=1003 WHERE id=?', (self.task,))
        with self.assertRaises(Denied):
            self.read()

    def test_bounded_latest_actions_and_all_approval_states(self):
        ids = [self.action(i) for i in range(20)]
        result = parse_snapshot(self.read(), self.prompt)
        self.assertEqual(result['action_count'], 20)
        self.assertEqual([a['action_id'] for a in result['actions']], list(reversed(ids))[:16])
        self.assertEqual(len(result['approvals']), 20)
        self.assertEqual({a['state'] for a in result['approvals']}, {'approved'})

    def test_unallocated_prompt_is_visible_without_creating_task_or_authority(self):
        prompt = self.prompts.submit(human_uid=1002, request_key='c' * 32,
                                    prompt='queued', boot_id='boot')['id']
        before = self.state.db.total_changes
        result = parse_snapshot(self.read(prompt_id=prompt), prompt)
        self.assertEqual(result['action_count'], 0)
        self.assertEqual(result['actions'], [])
        self.assertEqual(result['approvals'], [])
        self.assertIsNone(result['prompt']['task_id'])
        self.assertEqual(self.state.db.total_changes, before)

    def test_client_binding_no_retry_and_no_submission(self):
        result = self.read()
        with patch('mano_prompt.task_status.rpc',
                   return_value=dict(ok=True, snapshot=result)) as rpc:
            self.assertEqual(read_task_status(self.prompt), result)
            rpc.assert_called_once_with(b'\x01\x07' + self.prompt.encode())
        with patch('mano_prompt.task_status.rpc', side_effect=TimeoutError()) as rpc:
            with self.assertRaises(TimeoutError):
                read_task_status(self.prompt)
            self.assertEqual(rpc.call_count, 1)
        with self.assertRaises(ValueError):
            packet('not-an-id')

    def test_client_rejects_secret_fields_bad_states_verification_and_task_substitution(self):
        self.action(1)
        result = self.read()
        for modified in (
            result | dict(nonce='secret'), result | dict(action_count=True),
            result | dict(actions=[]),
            result | dict(approvals=result['approvals'] * 65),
            result | dict(actions=[result['actions'][0] | dict(effect_verified=True)]),
            result | dict(actions=[result['actions'][0] | dict(state='completed')]),
            result | dict(approvals=[result['approvals'][0] | dict(grant_id='a' * 32)]),
        ):
            with self.subTest(modified=modified), self.assertRaises(ValueError):
                parse_snapshot(modified, self.prompt)
        model = Intake()
        model.select(result['prompt'])
        token = model.token()
        self.assertTrue(model.update_snapshot(token, result))
        self.assertIn('effect not verified', model.display())
        self.assertIn('trusted terminal', model.display())
        with self.assertRaises(ValueError):
            model.update_snapshot(token, result | dict(
                prompt=result['prompt'] | dict(task_id='d'*32)))
        self.assertEqual(model.current['task_id'], self.task)
        model.select(result['prompt'])
        self.assertFalse(model.update_snapshot(token, result))

    def test_first_snapshot_before_any_approval_helper_is_read_only(self):
        fresh = State(Path(self.temp.name).resolve() / 'fresh')
        try:
            prompts = Prompts(fresh)
            receipt = prompts.submit(human_uid=1002, request_key='e' * 32,
                                     prompt='first', boot_id='boot')
            task = fresh.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
                                    resource_id='f' * 32, classification='internal', boot_id='boot')
            prompts.claim(receipt['id'], human_uid=1002, boot_id='boot')
            prompts.attach(receipt['id'], task, human_uid=1002, boot_id='boot')
            before = fresh.db.total_changes
            result = snapshot(fresh, human_uid=1002, prompt_id=receipt['id'], boot_id='boot', now=1)
            self.assertEqual(result['approvals'], [])
            self.assertEqual(result['actions'], [])
            self.assertEqual(fresh.db.total_changes, before)
        finally:
            fresh.close()
