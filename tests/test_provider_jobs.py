import json
import unittest
from unittest.mock import patch

import test_model_outcomes as outcomes

from mano_broker.model_budget import ModelBudget
from mano_broker.model_pricing import PricePolicy
from mano_broker.provider_jobs import ProviderJobs
from mano_broker.state import Denied, State


class ProviderJobTests(unittest.TestCase):
    tearDown = outcomes.ModelOutcomeTests.tearDown

    def setUp(self):
        outcomes.ModelOutcomeTests.setUp(self)
        self.jobs = ProviderJobs(self.state)
        ModelBudget(self.state).configure(self.task, authenticated_human_uid=1002,
            boot_id='boot', money=10, tokens=2000)
        self.policy = PricePolicy(model='snapshot', revision='synthetic', expires_unix=1000,
            input_context_tokens=1000, max_output_tokens=100,
            input_micro_usd_per_million=1001, output_micro_usd_per_million=2001)

    def prepare(self):
        return self.jobs.prepare(self.action, policy=self.policy, now=12, wall_time=100,
                                 boot_id='boot')

    def claim(self):
        return json.loads(self.jobs.claim(self.action, now=12, boot_id='boot'))

    def test_once_only_claim_binds_original_request_and_settles_original_quote(self):
        self.assertEqual(self.prepare(), self.proposal['args'])
        packet = self.claim()
        binding = packet['body']['binding']
        self.assertEqual(binding['task_id'], self.task)
        self.assertEqual(packet['body']['request']['args'], self.proposal['args'])
        with self.assertRaises(Denied):
            self.claim()
        with self.assertRaises(Denied):
            self.jobs.finish(self.action, self.packet, binding=binding | {'nonce': 'f' * 64},
                             boot_id='boot')
        result = self.jobs.finish(self.action, self.packet, binding=binding, boot_id='boot')
        self.assertEqual(result['usage']['total_tokens'], 5)
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM provider_jobs').fetchone()[0], 'finished')
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (1, 5, 1))

    def test_failed_authenticated_receipt_marks_unknown_and_retains_full_reserve(self):
        self.prepare()
        self.claim()
        with patch('mano_broker.provider_jobs.receive_response', side_effect=ValueError('denied')):
            with self.assertRaises(ValueError):
                self.jobs.receive(object(), self.action, expected_uid=1006, expected_gid=1006,
                                  boot_id='boot')
        with self.assertRaises(Denied):
            self.claim()
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM actions').fetchone()[0], 'unknown')
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (2, 1100, 0))

    def test_recovery_preserves_job_nonce_and_forbids_repeat_dispatch(self):
        self.prepare()
        original = self.claim()['body']['binding']
        self.state.close()
        self.state = State(self.directory)
        self.jobs = ProviderJobs(self.state)
        self.state.recover()
        self.assertEqual(self.jobs.original(self.action, 'boot')[3], original)
        with self.assertRaises(Denied):
            self.claim()
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 1)

    def test_stop_or_expired_grant_before_claim_prevents_dispatch(self):
        self.prepare()
        with self.assertRaises(Denied):
            self.jobs.claim(self.action, now=1000, boot_id='boot')
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.claim()
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM provider_jobs').fetchone()[0], 'prepared')
