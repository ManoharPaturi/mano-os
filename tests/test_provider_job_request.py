import json
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.stop_state import Snapshot
from mano_protocol.transport import Peer
from mano_provider.job_request import authorize, execute


class ProviderJobRequestTests(unittest.TestCase):
    def setUp(self):
        native = patch('mano_provider.job_request.snapshot', return_value=Snapshot(0, False))
        native.start()
        self.addCleanup(native.stop)
        self.request = dict(schema_version='1.0', task_id='a' * 32, resource_id='b' * 32,
            grant_id='c' * 32, capability='model.plan', idempotency_key='one', reason='plan',
            args=dict(provider='openai', model='synthetic', prompt='approved prompt',
                      max_output_tokens=100))
        self.binding = dict(task_id='a' * 32, action_id='d' * 32, boot_id='boot',
            nonce='e' * 64, request_sha256=ActionRequest.parse(
                canonical(self.request).encode()).digest)
        self.config = dict(provider='openai', model='synthetic',
                           max_output_tokens=100, enabled=True)
        self.packet = canonical(dict(schema_version='1.0', operation='generate',
            body=dict(binding=self.binding, request=self.request,
                      native_stop_generation=0,
                      grant_expires_monotonic=100, price_expires_unix=1000))).encode()

    def call(self, packet=None, **changes):
        args = dict(config=self.config, boot_id='boot', now=12, wall_time=100)
        with patch('mano_provider.job_request.pwd.getpwnam',
                   return_value=SimpleNamespace(pw_uid=999, pw_gid=999)):
            return authorize(packet or self.packet, Peer(42, 999, 999), **(args | changes))

    def test_exact_original_job_returns_only_bound_disclosure_arguments(self):
        binding, args = self.call()
        self.assertEqual(binding, self.binding)
        self.assertEqual(args, self.request['args'])
        self.assertNotIn('grant_id', args)
        self.assertNotIn('task_id', args)

    def test_wrong_boot_disabled_or_mismatched_fixed_policy_is_denied(self):
        with self.assertRaises(ValueError):
            self.call(boot_id='other')
        for change in (dict(enabled=False), dict(enabled=1), dict(model='other'),
                       dict(provider='other'), dict(max_output_tokens=99),
                       dict(max_output_tokens=True)):
            with self.assertRaises(ValueError):
                self.call(config=self.config | change)

    def test_changed_request_binding_and_added_authority_are_denied(self):
        for change in (dict(prompt='different prompt'), dict(max_output_tokens=101),
                       dict(api_key='must-never-be-forwarded')):
            envelope = json.loads(self.packet)
            envelope['body']['request']['args'].update(change)
            with self.assertRaises(ValueError):
                self.call(canonical(envelope).encode())
        with patch('mano_provider.job_request.pwd.getpwnam',
                   return_value=SimpleNamespace(pw_uid=999, pw_gid=999)):
            with self.assertRaises(ValueError):
                authorize(self.packet, Peer(42, 1004, 1004), config=self.config,
                          boot_id='boot', now=12, wall_time=100)

    def execute(self, connection, peer, **kwargs):
        with (
            patch('mano_provider.job_request.time.monotonic', return_value=12),
            patch('mano_provider.job_request.time.time', return_value=100),
        ):
            return execute(connection, self.packet, peer, **kwargs)

    def test_one_fixed_invocation_forwards_only_approved_args_and_sealed_reply(self):
        connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        with patch('mano_provider.job_request.pwd.getpwnam',
                   return_value=SimpleNamespace(pw_uid=999, pw_gid=999)), \
             patch('mano_provider.job_request.generate', return_value=b'ci-response') as generate, \
             patch('mano_provider.job_request.send_response') as send:
            self.execute(connection, Peer(42, 999, 999), config=self.config,
                    credential='ci-synthetic-key', boot_id='boot')
            generate.assert_called_once_with(self.request['args'], 'ci-synthetic-key')
            send.assert_called_once_with(connection, b'ci-response', binding=self.binding)

    def test_invalid_job_never_calls_provider_and_transport_failure_never_retries(self):
        connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        with patch('mano_provider.job_request.pwd.getpwnam',
                   return_value=SimpleNamespace(pw_uid=999, pw_gid=999)), \
             patch('mano_provider.job_request.generate',
                   side_effect=OSError('uncertain')) as call, \
             patch('mano_provider.job_request.send_response') as send:
            with self.assertRaises(ValueError):
                self.execute(connection, Peer(42, 999, 999),
                    config=self.config | {'enabled': False}, credential='ci-key', boot_id='boot')
            call.assert_not_called()
            with self.assertRaises(OSError):
                self.execute(connection, Peer(42, 999, 999), config=self.config,
                        credential='ci-key', boot_id='boot')
            call.assert_called_once()
            send.assert_not_called()

    def test_delayed_or_malformed_deadlines_deny_before_provider_invocation(self):
        for change in (dict(grant_expires_monotonic=46), dict(price_expires_unix=134),
                       dict(grant_expires_monotonic=True), dict(price_expires_unix=-1),
                       dict(price_expires_unix=10**1000)):
            envelope = json.loads(self.packet)
            envelope['body'].update(change)
            with self.assertRaises(ValueError):
                self.call(canonical(envelope).encode())
        with self.assertRaises(ValueError):
            self.call(now=66)  # Valid original packet delayed until less than35s remains.
        with self.assertRaises(ValueError):
            self.call(wall_time=966)

    def test_late_execution_never_reaches_fixed_provider_helper(self):
        connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        with (
            patch('mano_provider.job_request.pwd.getpwnam',
                  return_value=SimpleNamespace(pw_uid=999, pw_gid=999)),
            patch('mano_provider.job_request.time.monotonic', return_value=66),
            patch('mano_provider.job_request.time.time', return_value=100),
            patch('mano_provider.job_request.generate') as call,
        ):
            with self.assertRaises(ValueError):
                execute(connection, self.packet, Peer(42, 999, 999), config=self.config,
                        credential='ci-key', boot_id='boot')
            call.assert_not_called()

    def test_deadline_window_matches_fixed_installed_hard_runtime(self):
        from pathlib import Path

        from mano_provider.job_request import JOB_LIFETIME_SECONDS

        unit = (Path(__file__).resolve().parents[1] / 'packaging' / 'systemd'
                / 'mano-provider@.service').read_text().splitlines()
        runtime = [line.split('=', 1)[1] for line in unit if line.startswith('RuntimeMaxSec=')]
        self.assertEqual(runtime, [str(JOB_LIFETIME_SECONDS)])
        self.assertIn('KillSignal=SIGKILL', unit)

    def test_native_stop_and_rearm_invalidate_original_job(self):
        for native in (Snapshot(0, True), Snapshot(1, False), Snapshot(2, True)):
            with self.subTest(native=native), patch(
                'mano_provider.job_request.snapshot', return_value=native
            ), self.assertRaises(ValueError):
                self.call()

    def test_native_stop_read_failure_never_reaches_provider(self):
        connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        from mano_protocol.errors import Denied

        for error in (Denied('pending'), OSError('missing')):
            with (
                patch('mano_provider.job_request.snapshot', side_effect=error),
                patch('mano_provider.job_request.pwd.getpwnam',
                      return_value=SimpleNamespace(pw_uid=999, pw_gid=999)),
                patch('mano_provider.job_request.generate') as generate,
            ):
                with self.assertRaises((Denied, OSError)):
                    self.execute(connection, Peer(42, 999, 999), config=self.config,
                                 credential='ci-key', boot_id='boot')
                generate.assert_not_called()

    def test_native_generation_requires_exact_nonnegative_bounded_integer(self):
        for generation in (True, -1, 1.0, '0', 1 << 63, None):
            envelope = json.loads(self.packet)
            envelope['body']['native_stop_generation'] = generation
            with self.subTest(generation=generation), self.assertRaises(ValueError):
                self.call(canonical(envelope).encode())
