import getpass
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mano_broker.provider_setup import main, publish


class ProviderSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def test_atomic_private_single_link_install_and_no_overwrite(self):
        check = Mock()
        publish(self.fd, 'ci-only-key', check=check)
        target = self.path / 'openai'
        self.assertEqual(target.read_bytes(), b'ci-only-key')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(list(self.path.iterdir()), [target])
        check.assert_called_once()
        with self.assertRaises(ValueError):
            publish(self.fd, 'replacement', check=check)
        self.assertEqual(target.read_bytes(), b'ci-only-key')

    def test_stop_change_and_bad_key_leave_no_destination_or_staging_file(self):
        for key in ('bad\nkey', '', 'x' * 4097, 'unicode-\u03b1'):
            with self.assertRaises(ValueError):
                publish(self.fd, key, check=Mock())
        with self.assertRaises(ValueError):
            publish(self.fd, 'ci-only-key', check=Mock(side_effect=ValueError('rearmed')))
        self.assertEqual(list(self.path.iterdir()), [])

    def test_concurrent_destination_is_never_replaced(self):
        target = self.path / 'openai'
        def raced():
            target.write_bytes(b'other-operator')
        with self.assertRaises(FileExistsError):
            publish(self.fd, 'new-key', check=raced)
        self.assertEqual(target.read_bytes(), b'other-operator')
        self.assertEqual(list(self.path.iterdir()), [target])

    def test_symlink_destination_is_preserved_without_following(self):
        other = self.path / 'other'
        other.write_bytes(b'preserved')
        (self.path / 'openai').symlink_to(other)
        with self.assertRaises(ValueError):
            publish(self.fd, 'new-key', check=Mock())
        self.assertEqual(other.read_bytes(), b'preserved')

    def test_nonroot_or_pipe_denied_before_secret_or_filesystem(self):
        with (
            patch('mano_broker.provider_setup.sys.argv', ['provider-setup']),
            patch('mano_broker.provider_setup.sys.platform', 'linux'),
            patch('mano_broker.provider_setup.os.getuid', return_value=1002),
            patch('mano_broker.provider_setup.getpass.getpass') as secret,
            patch('mano_broker.provider_setup.directory') as directory,
            patch('mano_broker.provider_setup.sys.stdout', io.StringIO()),
        ):
            self.assertEqual(main(), 1)
            secret.assert_not_called()
            directory.assert_not_called()
        with (
            patch('mano_broker.provider_setup.sys.argv', ['provider-setup']),
            patch('mano_broker.provider_setup.sys.platform', 'linux'),
            patch('mano_broker.provider_setup.os.getuid', return_value=0),
            patch('mano_broker.provider_setup.os.geteuid', return_value=0),
            patch('mano_broker.provider_setup.os.getegid', return_value=0),
            patch('mano_broker.provider_setup.sys.stdin', io.StringIO()),
            patch('mano_broker.provider_setup.sys.stdout', io.StringIO()),
            patch('mano_broker.provider_setup.getpass.getpass') as secret,
        ):
            self.assertEqual(main(), 1)
            secret.assert_not_called()

    def test_no_echo_failure_denied_without_publication(self):
        with (
            patch('mano_broker.provider_setup.sys.argv', ['provider-setup']),
            patch('mano_broker.provider_setup.operator_terminal'),
            patch('mano_broker.provider_setup.stopped'),
            patch('mano_broker.provider_setup.directory', return_value=os.dup(self.fd)),
            patch('mano_broker.provider_setup.getpass.getpass',
                  side_effect=getpass.GetPassWarning('no echo unavailable')),
            patch('mano_broker.provider_setup.sys.stdout', io.StringIO()),
        ):
            self.assertEqual(main(), 1)
        self.assertEqual(list(self.path.iterdir()), [])
