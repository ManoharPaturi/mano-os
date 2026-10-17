import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_egress.service import serve
from mano_protocol.stop_state import Snapshot
from mano_protocol.transport import CREDENTIALS


class EgressServiceTests(unittest.TestCase):
    def setUp(self):
        self.connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
        self.connection.getsockopt.return_value = CREDENTIALS.pack(42, 998, 998)
        self.address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                        ('93.184.216.34', 443))

    def call(self, enabled=True, snapshots=None):
        upstream = Mock()
        with (
            patch('mano_egress.service.pwd.getpwnam',
                  return_value=SimpleNamespace(pw_uid=998, pw_gid=998)),
            patch('mano_egress.service.enabled', return_value=enabled),
            patch('mano_egress.service.socket.SO_PEERCRED',
                  getattr(socket, 'SO_PEERCRED', 17), create=True),
            patch('mano_egress.service.snapshot', return_value=Snapshot(0, False),
                  side_effect=snapshots),
            patch('mano_egress.service.addresses', return_value=[self.address]) as dns,
            patch('mano_egress.service.socket.socket') as constructor,
            patch('mano_egress.service.time.monotonic', return_value=12),
            patch('mano_egress.service.relay', return_value={'forwarded': True}) as forward,
        ):
            constructor.return_value.__enter__.return_value = upstream
            try:
                return serve(self.connection), upstream, forward
            finally:
                self.dns_calls = dns.call_count
                self.socket_calls = constructor.call_count

    def test_disabled_and_counterfeit_peer_deny_before_dns_or_network(self):
        with self.assertRaises(ValueError):
            self.call(enabled=False)
        self.assertEqual((self.dns_calls, self.socket_calls), (0, 0))
        self.connection.getsockopt.return_value = CREDENTIALS.pack(42, 1004, 1004)
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual((self.dns_calls, self.socket_calls), (0, 0))

    def test_one_fixed_numeric_connect_and_opaque_relay_without_retry(self):
        result, upstream, forward = self.call()
        self.assertEqual(result, {'forwarded': True})
        self.assertEqual((self.dns_calls, self.socket_calls), (1, 1))
        upstream.connect.assert_called_once_with(('93.184.216.34', 443))
        forward.assert_called_once_with(self.connection, upstream, deadline=42)

    def test_stop_or_changed_generation_prevents_numeric_connect(self):
        for states in ([Snapshot(0, True)], [Snapshot(0, False), Snapshot(1, False)]):
            with self.assertRaises(ValueError):
                self.call(snapshots=states)
            self.assertEqual(self.socket_calls, 0)
