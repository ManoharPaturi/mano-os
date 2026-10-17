import socket
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mano_broker.provider_worker import ProviderWorker
from mano_broker.state import Denied
from mano_protocol.stop_state import Snapshot
from mano_protocol.transport import CREDENTIALS


class ProviderWorkerTests(unittest.TestCase):
    def setUp(self):
        self.jobs = MagicMock()
        self.jobs.claim.return_value = b'original'
        self.jobs.original.return_value = ({'state': 'executing'},
            SimpleNamespace(grant_id='grant'), {'state': 'dispatching'}, {})
        self.jobs.state.db.execute.return_value.fetchone.return_value = dict(
            revoked=0, native_generation=0, expires=100)
        self.jobs.receive.return_value = {'saved': True}
        self.connection = MagicMock()
        self.connection.getsockopt.return_value = CREDENTIALS.pack(1, 0, 0)
        self.connection.send.side_effect = len
        self.worker = ProviderWorker(self.jobs, boot_id='boot')
        self.now = 12
        self.readable = False
        def account(name):
            return SimpleNamespace(pw_uid=999 if name == 'mano-broker' else 998, pw_gid=998)
        patches = dict(
            **{'pwd.getpwnam': dict(side_effect=account), 'os.geteuid': dict(return_value=999),
               'socket.socket': dict(return_value=self.connection),
               'load_policy': dict(return_value=object()),
               'time.monotonic': dict(side_effect=lambda: self.now),
               'time.time': dict(return_value=100),
               'snapshot': dict(return_value=Snapshot(0, False)),
               'select.select': dict(side_effect=lambda *args: (
                   [self.connection] if self.readable else [], [], []))})
        for name, options in patches.items():
            context = patch('mano_broker.provider_worker.' + name, **options)
            context.start()
            self.addCleanup(context.stop)
        for name, fallback in (('SO_PASSCRED', 16), ('SO_PEERCRED', 17)):
            context = patch('mano_broker.provider_worker.socket.' + name,
                            getattr(socket, name, fallback), create=True)
            context.start()
            self.addCleanup(context.stop)

    def test_pending_provider_never_blocks_or_receives_until_readable(self):
        self.worker.launch('one')
        self.connection.setblocking.assert_called_once_with(False)
        self.assertIsNone(self.worker.poll('one'))
        self.jobs.receive.assert_not_called()
        self.readable = True
        self.assertEqual(self.worker.poll('one'), {'saved': True})
        self.jobs.receive.assert_called_once_with(self.connection, 'one',
            expected_uid=998, expected_gid=998, boot_id='boot')
        self.connection.send.assert_called_once_with(b'original')
        self.connection.close.assert_called_once()
        self.jobs.uncertain.assert_not_called()

    def test_deadline_or_stop_retains_reserve_without_retry(self):
        self.worker.launch('one')
        self.now = 52
        with self.assertRaises(Denied):
            self.worker.poll('one')
        self.jobs.uncertain.assert_called_once_with('one', boot_id='boot')
        self.jobs.receive.assert_not_called()
        self.connection.close.assert_called_once()
        self.assertFalse(self.worker.pending)

    def test_rearm_before_receipt_invalidates_original_grant(self):
        self.worker.launch('one')
        with patch('mano_broker.provider_worker.snapshot', return_value=Snapshot(1, False)):
            with self.assertRaises(Denied):
                self.worker.poll('one')
        self.jobs.receive.assert_not_called()
        self.jobs.uncertain.assert_called_once()

    def test_nonblocking_send_failure_is_uncertain_and_never_retried(self):
        self.connection.send.side_effect = BlockingIOError()
        with self.assertRaises(BlockingIOError):
            self.worker.launch('one')
        self.jobs.uncertain.assert_called_once()
        self.connection.send.assert_called_once()
        self.connection.close.assert_called_once()
        self.assertFalse(self.worker.pending)

    def test_capacity_duplicate_and_close_release_every_original(self):
        self.worker.launch('one')
        with self.assertRaises(Denied):
            self.worker.launch('one')
        self.worker.launch('two')
        with self.assertRaises(Denied):
            self.worker.launch('three')
        self.worker.close()
        self.assertEqual(self.jobs.uncertain.call_count, 2)
        with self.assertRaises(Denied):
            self.worker.launch('three')

    def test_counterfeit_listener_never_reserves(self):
        self.connection.getsockopt.return_value = CREDENTIALS.pack(42, 1004, 1004)
        with self.assertRaises(Denied):
            self.worker.launch('one')
        self.jobs.prepare.assert_not_called()
        self.connection.send.assert_not_called()
        self.connection.close.assert_called_once()

    def test_unreadable_stop_authority_cancels_pending_without_receiving(self):
        self.worker.launch('one')
        with patch('mano_broker.provider_worker.snapshot', side_effect=OSError('missing')):
            with self.assertRaises(OSError):
                self.worker.poll('one')
        self.jobs.receive.assert_not_called()
        self.jobs.uncertain.assert_called_once()
        self.connection.close.assert_called_once()

    def test_bad_receipt_closes_original_without_second_send(self):
        self.worker.launch('one')
        self.readable = True
        self.jobs.receive.side_effect = ValueError('bad sealed receipt')
        with self.assertRaises(ValueError):
            self.worker.poll('one')
        self.jobs.uncertain.assert_called_once()
        self.connection.send.assert_called_once()
        self.connection.close.assert_called_once()
        self.assertFalse(self.worker.pending)

    def test_close_releases_all_sockets_even_if_journal_settlement_fails(self):
        self.worker.launch('one')
        self.worker.launch('two')
        self.jobs.original.side_effect = OSError('journal unavailable')
        with self.assertRaises(OSError):
            self.worker.close()
        self.assertFalse(self.worker.pending)
        self.assertEqual(self.connection.close.call_count, 2)
