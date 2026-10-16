import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.registry import Registry
from mano_broker.state import Denied, State
from mano_protocol.actions import ActionRequest, canonical


class ModelDisclosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.task = self.state.create_task(human_uid=1002, caller_uid=1005, mode='supervised',
            resource_id='a' * 32, classification='sensitive', boot_id='boot')
        self.proposal = dict(schema_version='1.0', task_id=self.task, resource_id='a' * 32,
            capability='model.plan', args=dict(provider='openai', model='explicit-snapshot',
                prompt='human goal', max_output_tokens=100), idempotency_key='cloud-one',
            reason='Generate a proposed workspace operation')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def parse(self, proposal, grant='0' * 32):
        return ActionRequest.parse(canonical(proposal | {'grant_id': grant}).encode())

    def approve(self):
        queue = Approvals(self.state)
        pending = queue.request(self.proposal, caller_uid=1005, now=10, boot_id='boot')
        view = queue.view(pending['approval_id'], human_uid=1002)
        self.assertEqual(view['capability'], 'model.plan')
        self.assertEqual(view['args'], self.proposal['args'])
        grant = queue.approve(pending['approval_id'], authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'], now=11,
            boot_id='boot')
        return grant

    def test_exact_disclosure_and_budget_are_bound_to_human_approval(self):
        grant = self.approve()
        for change in (dict(provider='other'), dict(model='other'), dict(prompt='secret'),
                       dict(max_output_tokens=101)):
            with self.assertRaises(ValueError):
                request = self.parse(
                    self.proposal | {'args': self.proposal['args'] | change}, grant)
                self.state.authorize(request, caller_uid=1005, now=12, boot_id='boot')
        request = self.parse(self.proposal, grant)
        action, fresh = self.state.authorize(request, caller_uid=1005, now=12, boot_id='boot')
        self.assertTrue(fresh)
        replay, fresh = self.state.authorize(request, caller_uid=1005, now=12, boot_id='boot')
        self.assertFalse(fresh)
        self.assertEqual(action['id'], replay['id'])

    def test_credentials_endpoints_and_unbounded_input_cannot_enter_disclosure(self):
        for change in (dict(endpoint='http://127.0.0.1'), dict(api_key='secret'),
                dict(headers={'Authorization': 'secret'}), dict(max_output_tokens=True),
                dict(max_output_tokens=8193), dict(prompt='x' * 8193), dict(model='bad\nmodel')):
            with self.assertRaises(ValueError):
                self.parse(self.proposal | {'args': self.proposal['args'] | change})

    def test_production_preparation_denies_before_consuming_grant_or_creating_action(self):
        grant = self.approve()
        registry = Registry()
        try:
            with self.assertRaises(Denied):
                registry.prepare(self.state, self.parse(self.proposal, grant), caller_uid=1005,
                                 now=12, boot_id='boot')
            self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 0)
            self.assertEqual(self.state.db.execute('SELECT used FROM grants').fetchone()[0], 0)
        finally:
            registry.close()
