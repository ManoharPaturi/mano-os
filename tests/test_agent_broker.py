import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_core.broker import BrokerClient


class PublicClientGuards(unittest.TestCase):
    def test_root_account_and_private_operations_cannot_connect(self):
        with patch('mano_core.broker.pwd.getpwnam', return_value=SimpleNamespace(pw_uid=0)):
            with self.assertRaises(ValueError):
                BrokerClient()
        account = SimpleNamespace(pw_uid=999, pw_gid=999)
        with patch('mano_core.broker.pwd.getpwnam', return_value=account):
            client = BrokerClient()
        with patch('mano_core.broker.socket.socket') as connect:
            for operation in ('capture_artifact', 'confirm_approval', 'verify', 'rearm',
                              'declare_artifact_contract', 'check_artifact_contract'):
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    client(dict(operation=operation))
            with self.assertRaises(ValueError):
                client(dict(operation='status', body='x' * 65536))
            client.pidfd = 42
            with patch('mano_core.broker.select.select', return_value=([42], [], [])):
                with self.assertRaises(ValueError):
                    client(dict(operation='status'))
            client.pidfd = None
            client.close()
            with self.assertRaises(ValueError):
                client(dict(operation='status'))
            connect.assert_not_called()
