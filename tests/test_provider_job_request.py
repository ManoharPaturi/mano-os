import json
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.transport import Peer
from mano_provider.job_request import authorize, execute


class ProviderJobRequestTests(unittest.TestCase):
    def setUp(self):
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
            body=dict(binding=self.binding, request=self.request))).encode()

    def call(self, packet=None, **changes):
        args = dict(config=self.config, boot_id='boot')
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
                authorize(self.packet, Peer(42, 1004, 1004), config=self.config, boot_id='boot')

    def test_one_fixed_invocation_forwards_only_approved_args_and_sealed_reply(self):
        connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        with patch('mano_provider.job_request.pwd.getpwnam',
                   return_value=SimpleNamespace(pw_uid=999, pw_gid=999)), \
             patch('mano_provider.job_request.generate', return_value=b'ci-response') as generate, \
             patch('mano_provider.job_request.send_response') as send:
            execute(connection, self.packet, Peer(42, 999, 999), config=self.config,
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
                execute(connection, self.packet, Peer(42, 999, 999),
                    config=self.config | {'enabled': False}, credential='ci-key', boot_id='boot')
            call.assert_not_called()
            with self.assertRaises(OSError):
                execute(connection, self.packet, Peer(42, 999, 999), config=self.config,
                        credential='ci-key', boot_id='boot')
            call.assert_called_once()
            send.assert_not_called()
