import json
import os
import socket
import sys
import unittest
from unittest.mock import patch

import test_model_outcomes as outcomes

from mano_broker.model_budget import ModelBudget
from mano_broker.model_pricing import PricePolicy
from mano_broker.provider_jobs import ProviderJobs
from mano_broker.state import Denied, State
from mano_protocol.stop_state import Snapshot


class ProviderJobTests(unittest.TestCase):
    tearDown = outcomes.ModelOutcomeTests.tearDown

    def setUp(self):
        native = patch('mano_provider.job_request.snapshot', return_value=Snapshot(0, False))
        native.start()
        self.addCleanup(native.stop)
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
        return json.loads(self.jobs.claim(self.action, now=12, wall_time=100, boot_id='boot'))

    def test_once_only_claim_binds_original_request_and_settles_original_quote(self):
        self.assertEqual(self.prepare(), self.proposal['args'])
        packet = self.claim()
        binding = packet['body']['binding']
        from types import SimpleNamespace

        from mano_protocol.actions import canonical
        from mano_protocol.transport import Peer
        from mano_provider.job_request import authorize

        config = dict(provider='openai', model='snapshot', enabled=True, max_output_tokens=100)
        with patch('mano_provider.job_request.pwd.getpwnam',
                   return_value=SimpleNamespace(pw_uid=999, pw_gid=999)):
            bound, args = authorize(canonical(packet).encode(), Peer(42, 999, 999),
                                    config=config, boot_id='boot', now=12, wall_time=100)
        self.assertEqual(bound, binding)
        self.assertEqual(args, self.proposal['args'])
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
            self.jobs.claim(self.action, now=1000, wall_time=100, boot_id='boot')
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.claim()
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM provider_jobs').fetchone()[0], 'prepared')

    def test_price_expiry_between_preparation_and_dispatch_denies_claim(self):
        self.prepare()
        with self.assertRaises(Denied):
            self.jobs.claim(self.action, now=12, wall_time=1000, boot_id='boot')
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM provider_jobs').fetchone()[0], 'prepared')
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (2, 1100, 0))

    def test_saved_price_mismatch_cannot_be_replaced_by_another_model_at_dispatch(self):
        self.prepare()
        saved = json.loads(self.state.db.execute(
            'SELECT policy_json FROM model_prices').fetchone()[0])
        saved['model'] = 'other-model'
        self.state.db.execute('UPDATE model_prices SET policy_json=?', (json.dumps(saved),))
        with self.assertRaises(Denied):
            self.claim()
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM provider_jobs').fetchone()[0], 'prepared')

    @unittest.skipUnless(sys.platform == 'linux' and os.getuid() != 0,
                         'Linux non-root sealed handoff required')
    def test_provider_handler_to_sealed_receipt_and_original_priced_settlement(self):
        from types import SimpleNamespace

        from mano_protocol.actions import canonical
        from mano_protocol.transport import Peer
        from mano_provider.job_request import execute

        self.prepare()
        envelope = self.claim()
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with sender, receiver:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            receiver.settimeout(1)
            sender.settimeout(1)
            with patch('mano_provider.job_request.pwd.getpwnam',
                       return_value=SimpleNamespace(pw_uid=999, pw_gid=999)), \
                 patch('mano_provider.job_request.generate', return_value=self.packet) as call:
                with (
                    patch('mano_provider.job_request.time.monotonic', return_value=12),
                    patch('mano_provider.job_request.time.time', return_value=100),
                ):
                    execute(sender, canonical(envelope).encode(), Peer(42, 999, 999),
                        config=dict(provider='openai', model='snapshot', enabled=True,
                                    max_output_tokens=100),
                        credential='ci-synthetic-key', boot_id='boot')
                call.assert_called_once_with(self.proposal['args'], 'ci-synthetic-key')
            result = self.jobs.receive(receiver, self.action, expected_uid=os.getuid(),
                                       expected_gid=os.getgid(), boot_id='boot')
        self.assertEqual(result['usage']['total_tokens'], 5)
        self.assertEqual(self.state.db.execute(
            'SELECT state FROM provider_jobs').fetchone()[0], 'finished')
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT money,tokens,settled FROM model_reservations').fetchone()), (1, 5, 1))

    def test_original_grant_generation_is_not_refreshed_at_dispatch(self):
        self.state.db.execute("UPDATE meta SET value=1 WHERE key='native_generation'")
        self.prepare()
        packet = self.claim()
        self.assertEqual(packet['body']['native_stop_generation'], 0)
        from types import SimpleNamespace

        from mano_protocol.actions import canonical
        from mano_protocol.transport import Peer
        from mano_provider.job_request import authorize

        with (
            patch('mano_provider.job_request.snapshot', return_value=Snapshot(1, False)),
            patch('mano_provider.job_request.pwd.getpwnam',
                  return_value=SimpleNamespace(pw_uid=999, pw_gid=999)),
        ):
            with self.assertRaises(ValueError):
                authorize(canonical(packet).encode(), Peer(42, 999, 999),
                    config=dict(provider='openai', model='snapshot', enabled=True,
                                max_output_tokens=100), boot_id='boot', now=12, wall_time=100)

    def test_unbound_legacy_grant_cannot_dispatch(self):
        self.state.db.execute('UPDATE grants SET native_generation=-1')
        self.prepare()
        with self.assertRaises(Denied):
            self.claim()

    def test_old_journal_migration_revokes_model_authority(self):
        self.state.db.execute('ALTER TABLE grants DROP COLUMN native_generation')
        self.state.close()
        self.state = State(self.directory)
        grant = self.state.db.execute('SELECT revoked,native_generation FROM grants').fetchone()
        self.assertEqual(tuple(grant), (1, -1))
