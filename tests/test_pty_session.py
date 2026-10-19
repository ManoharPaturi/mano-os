import subprocess
import unittest
from unittest.mock import Mock, patch

from mano_broker.pty_session import INPUT_LIMIT, TaskPTY, geometry


class TaskPTYGuards(unittest.TestCase):
    def worker(self):
        worker = TaskPTY.__new__(TaskPTY)
        worker.closed, worker.reason, worker.master = False, 'running', 42
        worker.input_bytes, worker.output_bytes, worker.deadline = 0, 0, float('inf')
        worker.revoked = lambda: False
        worker.process = Mock(pid=123)
        worker.process.poll.return_value = None
        worker.process.wait.return_value = -9
        return worker

    def test_bad_geometry_budget_and_revocation_never_allocate_a_pty(self):
        for rows, columns in ((True, 80), (0, 80), (201, 80), (24, 401)):
            with self.assertRaises(ValueError):
                geometry(rows, columns)
        with patch('mano_broker.pty_session.os.openpty') as allocate:
            for timeout in (True, 0, 301):
                with self.assertRaises(ValueError):
                    TaskPTY(3, 4, ['true'], timeout=timeout, revoked=lambda: False)
            with patch('mano_broker.pty_session.command', return_value=['fixed']):
                with self.assertRaises(PermissionError):
                    TaskPTY(3, 4, ['true'], timeout=1, revoked=lambda: True)
            allocate.assert_not_called()

    def test_root_or_nonlinux_denied_before_allocation(self):
        with patch('mano_broker.sandbox.sys.platform', 'darwin'), \
             patch('mano_broker.pty_session.os.openpty') as allocate:
            with self.assertRaises(PermissionError):
                TaskPTY(3, 4, ['true'], timeout=1, revoked=lambda: False)
            allocate.assert_not_called()

    def test_partial_input_is_charged_once_and_never_retried(self):
        worker = self.worker()
        with patch('mano_broker.pty_session.os.write', return_value=2) as write:
            self.assertEqual(worker.write(b'four'), 2)
            self.assertEqual(worker.input_bytes, 4)
            write.assert_called_once_with(42, b'four')
            worker.input_bytes = INPUT_LIMIT
            with self.assertRaises(ValueError):
                worker.write(b'x')
            self.assertEqual(write.call_count, 1)

    def test_revocation_and_bad_observer_close_before_input(self):
        for value in (True, 'invalid'):
            worker = self.worker()
            worker.revoked = lambda value=value: value
            with patch.object(worker, 'close') as close, \
                 patch('mano_broker.pty_session.os.write') as write:
                with self.assertRaises((ValueError, PermissionError)):
                    worker.write(b'x')
                close.assert_called_once_with('revoked')
                write.assert_not_called()

    def test_close_releases_master_even_when_process_wait_fails(self):
        worker = self.worker()
        worker.process.wait.side_effect = subprocess.TimeoutExpired('fixed', 5)
        with patch('mano_broker.pty_session.os.killpg'), \
             patch('mano_broker.pty_session.os.close') as close:
            with self.assertRaises(subprocess.TimeoutExpired):
                worker.close('unknown')
            close.assert_called_once_with(42)
            self.assertEqual(worker.master, -1)

    def test_resize_is_fixed_and_output_limit_closes_instead_of_truncating_success(self):
        worker = self.worker()
        with patch('mano_broker.pty_session.fcntl.ioctl') as resize:
            worker.resize(30, 100)
            resize.assert_called_once()
            with self.assertRaises(ValueError):
                worker.resize(0, 100)
        worker.output_bytes = 65536
        with patch('mano_broker.pty_session.os.read', return_value=b'x'), \
             patch.object(worker, 'close') as close:
            with self.assertRaises(OverflowError):
                worker.read()
            close.assert_called_once_with('output-limit')
