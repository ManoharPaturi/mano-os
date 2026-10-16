import unittest

import test_model_outcomes as outcomes

from mano_broker.model_budget import ModelBudget
from mano_broker.state import Denied


class ModelBudgetTests(unittest.TestCase):
    tearDown = outcomes.ModelOutcomeTests.tearDown

    def setUp(self):
        outcomes.ModelOutcomeTests.setUp(self)
        self.budget = ModelBudget(self.state)

    def configure(self, **changes):
        args = dict(authenticated_human_uid=1002, boot_id='boot', money=100, tokens=1000)
        self.budget.configure(self.task, **(args | changes))

    def begin(self, **changes):
        args = dict(now=12, boot_id='boot', money=80, tokens=800)
        return self.budget.begin(self.action, **(args | changes))

    def test_absent_exhausted_and_wrong_authority_fail_before_attempt(self):
        with self.assertRaises(Denied):
            self.begin()
        for changes in (dict(authenticated_human_uid=0), dict(boot_id='other')):
            with self.assertRaises(Denied):
                self.configure(**changes)
        self.configure()
        for changes in (dict(money=101), dict(tokens=1001)):
            with self.assertRaises(Denied):
                self.begin(**changes)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 0)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_reservations').fetchone()[0], 0)

    def test_atomic_reservation_reopen_and_unknown_never_refund(self):
        self.configure()
        self.begin()
        with self.assertRaises(Denied):
            self.begin()
        self.state.recover()
        with self.assertRaises(Denied):
            self.budget.settle(self.action, boot_id='boot', money=0, tokens=0)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (80, 800, 0))
        self.state.close()
        from mano_broker.state import State
        self.state = State(self.directory)
        self.budget = ModelBudget(self.state)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (80, 800, 0))
        with self.assertRaises(Denied):
            self.configure(money=200)

    def test_start_failure_rolls_back_reservation_and_success_settles_once(self):
        self.configure()
        with self.assertRaises(Denied):
            self.begin(now=10000)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_reservations').fetchone()[0], 0)
        self.begin()
        self.store.finish(self.action, self.packet, boot_id='boot')
        with self.assertRaises(Denied):
            self.budget.settle(self.action, boot_id='boot', money=81, tokens=5)
        with self.assertRaises(Denied):
            self.budget.settle(self.action, boot_id='boot', money=40, tokens=4)
        self.budget.settle(self.action, boot_id='boot', money=40, tokens=5)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (40, 5, 1))
        with self.assertRaises(Denied):
            self.budget.settle(self.action, boot_id='boot', money=0, tokens=0)

    def test_invalid_numeric_budgets_and_latched_configuration(self):
        for value in (True, 0, -1, 1.5, 10**20):
            with self.assertRaises(ValueError):
                self.configure(money=value)
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.configure()

    def test_second_call_cannot_spend_already_reserved_task_budget(self):
        import json

        from mano_protocol.actions import ActionRequest, canonical

        self.configure()
        self.begin()
        self.state.db.execute('UPDATE grants SET max_count=2')
        value = json.loads(self.state.db.execute(
            'SELECT request_json FROM actions WHERE id=?', (self.action,)).fetchone()[0])
        value['idempotency_key'] = 'second-call'
        request = ActionRequest.parse(canonical(value).encode())
        second, _ = self.state.authorize(request, caller_uid=1005, now=12, boot_id='boot')
        with self.assertRaises(Denied):
            self.budget.begin(second['id'], now=12, boot_id='boot', money=80, tokens=800)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 1)

    def test_stop_retains_full_reservation_and_public_mutations_are_denied(self):
        from mano_broker.ipc import Peer, dispatch
        from mano_protocol.actions import canonical

        self.configure()
        self.begin()
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.budget.settle(self.action, boot_id='boot', money=0, tokens=0)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (80, 800, 0))
        for operation in ('configure_model_budget', 'reserve_model_budget', 'settle_model_budget'):
            packet = canonical(dict(schema_version='1.0', operation=operation,
                                    body=dict(task_id=self.task, action_id=self.action))).encode()
            with self.assertRaises(Denied):
                dispatch(self.state, packet, peer=Peer(42, 1005, 1005), now=15, boot_id='boot')
