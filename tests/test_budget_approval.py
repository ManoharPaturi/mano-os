import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.model_budget import ModelBudget
from mano_broker.registry import Registry
from mano_broker.state import Denied, State
from mano_protocol.actions import ActionRequest, canonical


class BudgetApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.task = self.state.create_task(human_uid=1002, caller_uid=1005, mode='supervised',
            resource_id='a' * 32, classification='sensitive', boot_id='boot')
        self.queue = Approvals(self.state)

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def request(self, key='budget-one', money=100, tokens=1000):
        proposal = dict(schema_version='1.0', task_id=self.task, resource_id='a' * 32,
            capability='model.set_budget', args=dict(money_micro_usd=money, tokens=tokens),
            idempotency_key=key, reason='Approve bounded task spending')
        pending = self.queue.request(proposal, caller_uid=1005, now=10, boot_id='boot')
        return proposal, self.queue.view(pending['approval_id'], human_uid=1002)

    def approve(self, view, **changes):
        args = dict(authenticated_human_uid=1002, nonce=view['nonce'],
            operation_digest=view['operation_digest'], now=11, boot_id='boot')
        return self.queue.approve(view['approval_id'], **(args | changes))

    def test_exact_human_budget_approval_applies_once_and_new_grant_increases(self):
        proposal, view = self.request()
        self.assertEqual(view['args'], proposal['args'])
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_budgets').fetchone()[0], 0)
        for changes in (dict(authenticated_human_uid=1003), dict(nonce='0' * 64),
                        dict(operation_digest='0' * 64), dict(boot_id='other'), dict(now=1000)):
            with self.assertRaises(Denied):
                self.approve(view, **changes)
        grant = self.approve(view)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money_limit,token_limit FROM model_budgets').fetchone()), (100, 1000))
        with self.assertRaises(Denied):
            ModelBudget(self.state).apply_grant(grant, now=12, boot_id='boot')
        _, higher = self.request('budget-two', money=200, tokens=2000)
        self.approve(higher)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money_limit,token_limit FROM model_budgets').fetchone()), (200, 2000))
        self.assertEqual(self.state.db.execute('SELECT sum(used) FROM grants').fetchone()[0], 2)

    def test_failed_lowering_rolls_back_grant_and_approval(self):
        _, view = self.request()
        self.approve(view)
        _, lower = self.request('budget-lower', money=99)
        with self.assertRaises(Denied):
            self.approve(lower)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM grants').fetchone()[0], 1)
        self.assertEqual(self.queue.status(lower['approval_id'], caller_uid=1005,
            now=12, boot_id='boot')['state'], 'pending')

    def test_budget_grant_cannot_be_dispatched_or_repurposed_as_model_disclosure(self):
        proposal, view = self.request()
        grant = self.approve(view)
        request = ActionRequest.parse(canonical(proposal | {'grant_id': grant}).encode())
        registry = Registry()
        try:
            with self.assertRaises(Denied):
                registry.prepare(self.state, request, caller_uid=1005, now=12, boot_id='boot')
        finally:
            registry.close()
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 0)
        _, pending = self.request('stopped')
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.approve(pending)
