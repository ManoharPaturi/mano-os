import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_protocol.actions import canonical
from mano_protocol.transport import Peer
from mano_provider.credentials import private_file
from mano_provider.service import health, main


class ProtectedProviderTests(unittest.TestCase):
    def test_private_credential_rejects_symlinks_modes_links_and_size(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            key = directory / 'api-key'
            key.write_bytes(b'ci-synthetic-key')
            key.chmod(0o400)
            self.assertEqual(private_file(directory, 'api-key', 4096), b'ci-synthetic-key')
            key.chmod(0o644)
            with self.assertRaises(ValueError):
                private_file(directory, 'api-key', 4096)
            key.chmod(0o400)
            os.link(key, directory / 'extra')
            with self.assertRaises(ValueError):
                private_file(directory, 'api-key', 4096)
            (directory / 'extra').unlink()
            with self.assertRaises(ValueError):
                private_file(directory, 'api-key', 1)
            key.unlink()
            key.symlink_to('config')
            with self.assertRaises(OSError):
                private_file(directory, 'api-key', 4096)
            with self.assertRaises(ValueError):
                private_file(directory, '../key', 4096)

    def test_only_broker_health_reads_credential_and_never_returns_key(self):
        config = dict(provider='openai', model='snapshot', enabled=False, max_output_tokens=100)
        packet = canonical(dict(schema_version='1.0', operation='health', body={})).encode()
        broker = SimpleNamespace(pw_uid=999, pw_gid=999)
        with patch('mano_provider.service.pwd.getpwnam', return_value=broker), \
             patch('mano_provider.service.load', return_value=(config, 'ci-synthetic-key')) as load:
            for uid in (0, 1002, 1004):
                with self.assertRaises(ValueError):
                    health(packet, Peer(42, uid, uid))
            load.assert_not_called()
            result = health(packet, Peer(42, 999, 999))
            self.assertIs(result['execution_enabled'], False)
            self.assertIs(result['credentials_present'], True)
            self.assertNotIn('ci-synthetic-key', canonical(result))
            load.assert_called_once()
            load.reset_mock()
            for operation in ('generate', 'begin_model_attempt'):
                denied = canonical(dict(
                    schema_version='1.0', operation=operation, body={})).encode()
                with self.assertRaises(ValueError):
                    health(denied, Peer(42, 999, 999))
            load.assert_not_called()

    def test_profile_failure_precedes_socket_or_credential_access(self):
        with patch('mano_provider.service.verify_current', side_effect=ValueError('profile')), \
             patch('mano_provider.service.socket.fromfd') as socket, \
             patch('mano_provider.service.load') as load:
            self.assertEqual(main(), 1)
            socket.assert_not_called()
            load.assert_not_called()
