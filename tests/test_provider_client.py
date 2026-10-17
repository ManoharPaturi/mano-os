import socket
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mano_broker.provider_client import PATH, run
from mano_broker.state import Denied
from mano_protocol.transport import CREDENTIALS


class ProviderClientTests(unittest.TestCase):
    def setUp(self):
        self.jobs = MagicMock()
        self.jobs.claim.return_value = b'one-original-packet'
        self.jobs.receive.return_value = {'saved': 'result'}
        self.jobs.original.return_value = ({'state': 'executing'}, None,
                                           {'state': 'dispatching'}, None)
        self.connection = MagicMock()
        self.connection.getsockopt.return_value = CREDENTIALS.pack(1, 0, 0)
        self.connection.send.side_effect = lambda packet: len(packet)
        self.socket = MagicMock()
        self.socket.return_value.__enter__.return_value = self.connection

    def call(self):
        def account(name):
            return SimpleNamespace(pw_uid=999 if name == 'mano-broker' else 998,
                                   pw_gid=999 if name == 'mano-broker' else 998)
        with (
            patch('mano_broker.provider_client.pwd.getpwnam', side_effect=account),
            patch('mano_broker.provider_client.os.geteuid', return_value=999),
            patch('mano_broker.provider_client.socket.socket', self.socket),
            patch('mano_broker.provider_client.socket.SO_PASSCRED',
                  getattr(socket, 'SO_PASSCRED', 16), create=True),
            patch('mano_broker.provider_client.socket.SO_PEERCRED',
                  getattr(socket, 'SO_PEERCRED', 17), create=True),
            patch('mano_broker.provider_client.time.monotonic', return_value=12),
            patch('mano_broker.provider_client.time.time', return_value=100),
        ):
            return run(self.jobs, 'a' * 32, policy=object(), boot_id='boot')

    def test_fixed_root_listener_one_claim_send_and_authenticated_receipt(self):
        self.assertEqual(self.call(), {'saved': 'result'})
        self.socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.connection.connect.assert_called_once_with(PATH)
        self.jobs.prepare.assert_called_once()
        self.jobs.claim.assert_called_once_with('a' * 32, now=12, wall_time=100, boot_id='boot')
        self.connection.send.assert_called_once_with(b'one-original-packet')
        self.jobs.receive.assert_called_once_with(self.connection, 'a' * 32,
            expected_uid=998, expected_gid=998, boot_id='boot')
        self.jobs.uncertain.assert_not_called()

    def test_counterfeit_or_unreachable_listener_denied_before_reservation(self):
        self.connection.getsockopt.return_value = CREDENTIALS.pack(42, 1004, 1004)
        with self.assertRaises(Denied):
            self.call()
        self.jobs.prepare.assert_not_called()
        self.connection.send.assert_not_called()
        self.connection.connect.side_effect = OSError('unreachable')
        with self.assertRaises(OSError):
            self.call()
        self.jobs.prepare.assert_not_called()

    def test_send_or_receipt_failure_marks_original_uncertain_without_retry(self):
        for stage in ('send', 'receive'):
            with self.subTest(stage=stage):
                self.jobs.reset_mock()
                self.connection.send.reset_mock()
                self.connection.send.side_effect = lambda packet: len(packet)
                self.jobs.receive.side_effect = None
                if stage == 'send':
                    self.connection.send.side_effect = OSError('lost send')
                else:
                    self.jobs.receive.side_effect = ValueError('lost receipt')
                with self.assertRaises((OSError, ValueError)):
                    self.call()
                self.jobs.claim.assert_called_once()
                self.connection.send.assert_called_once()
                self.jobs.uncertain.assert_called_once_with('a' * 32, boot_id='boot')
