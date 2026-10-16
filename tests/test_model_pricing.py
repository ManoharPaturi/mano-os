import unittest
from dataclasses import replace

import test_model_outcomes as outcomes

from mano_broker.model_budget import ModelBudget
from mano_broker.model_pricing import PricePolicy, begin_priced, finish_priced
from mano_broker.state import Denied


class ModelPricingTests(unittest.TestCase):
    tearDown = outcomes.ModelOutcomeTests.tearDown

    def setUp(self):
        outcomes.ModelOutcomeTests.setUp(self)
        # Synthetic rates only; these are not prices for any real provider model.
        self.policy = PricePolicy(model='snapshot', revision='synthetic-revision',
            expires_unix=1000, input_context_tokens=1000, max_output_tokens=100,
            input_micro_usd_per_million=1001, output_micro_usd_per_million=2001)
        ModelBudget(self.state).configure(self.task, authenticated_human_uid=1002,
            boot_id='boot', money=10, tokens=2000)

    def begin(self, policy=None, **changes):
        args = dict(now=12, boot_id='boot', wall_time=100)
        return begin_priced(self.state, self.action, policy=policy or self.policy,
                            **(args | changes))

    def test_conservative_integer_rounding_and_bound_revision_are_durable(self):
        self.assertEqual(self.policy.quote(self.proposal['args'], wall_time=100),
                         dict(money=2, tokens=1100))
        self.assertEqual(self.begin(), self.proposal['args'])
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens FROM model_reservations').fetchone()), (2, 1100))
        event = self.state.db.execute("SELECT details_json FROM events "
            "WHERE event='model-price-reservation'").fetchone()[0]
        self.assertIn('synthetic-revision', event)
        with self.assertRaises(Denied):
            self.begin()

    def test_stale_mismatched_or_unfunded_price_policy_never_starts_attempt(self):
        for policy in (replace(self.policy, model='different'),
                       replace(self.policy, expires_unix=100),
                       replace(self.policy, max_output_tokens=99),
                       replace(self.policy, input_micro_usd_per_million=10**9)):
            with self.assertRaises(Denied):
                self.begin(policy)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 0)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_reservations').fetchone()[0], 0)

    def test_invalid_numeric_policy_and_expired_grant_roll_back(self):
        for policy in (replace(self.policy, input_context_tokens=True),
                       replace(self.policy, input_micro_usd_per_million=1.5),
                       replace(self.policy, output_micro_usd_per_million=0)):
            with self.assertRaises(ValueError):
                self.begin(policy)
        with self.assertRaises(Denied):
            self.begin(now=10000)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_reservations').fetchone()[0], 0)

    def test_uncertain_priced_call_retains_full_conservative_reserve(self):
        self.begin()
        self.store.uncertain(self.action, boot_id='boot')
        with self.assertRaises(Denied):
            self.begin()
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (2, 1100, 0))

    def test_saved_price_settles_after_journal_reopen_and_rejects_excess_usage(self):
        import json

        from mano_broker.state import State
        from mano_protocol.actions import canonical

        self.begin()
        oversized = json.loads(self.packet)
        oversized['usage']['input_tokens'] = 1001
        oversized['usage']['total_tokens'] = 1004
        with self.assertRaises(Denied):
            finish_priced(self.state, self.action, canonical(oversized).encode(), boot_id='boot')
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM actions').fetchone()[0], 'executing')
        self.state.close()
        self.state = State(self.directory)
        # No replay/recover call: simulates durable custody reopened by the same
        # trusted executor, not a restarted dispatcher resending the API request.
        result = finish_priced(self.state, self.action, self.packet, boot_id='boot')
        self.assertEqual(result['usage']['total_tokens'], 5)
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (1, 5, 1))
        with self.assertRaises(Denied):
            finish_priced(self.state, self.action, self.packet, boot_id='boot')

    def test_settlement_failure_rolls_back_completed_result(self):
        self.begin()
        self.state.db.execute('UPDATE model_reservations SET money=0')
        with self.assertRaises(Denied):
            finish_priced(self.state, self.action, self.packet, boot_id='boot')
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM actions').fetchone()[0], 'executing')
        self.assertIsNone(self.state.db.execute(
            'SELECT result_json FROM model_attempts').fetchone()[0])
