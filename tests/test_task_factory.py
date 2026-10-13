import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_broker.task_factory import create_task
from mano_protocol.transport import CREDENTIALS


class TaskFactoryGuards(unittest.TestCase):
    def test_unprivileged_and_malformed_prompt_do_not_allocate_accounts(self):
        with patch('mano_broker.task_factory.os.geteuid', return_value=1004), \
             patch('mano_broker.task_factory.allocate_identity') as allocate:
            with self.assertRaises(PermissionError):
                create_task('goal')
            allocate.assert_not_called()
        with patch('mano_broker.task_factory.os.geteuid', return_value=0), \
             patch('mano_broker.task_factory.sys.platform', 'linux'), \
             patch('mano_broker.task_factory.allocate_identity') as allocate:
            for prompt in ('', 'x' * 8193, 'bad\0text', True):
                with self.assertRaises(ValueError):
                    create_task(prompt)
            allocate.assert_not_called()

    def test_uncertain_provisioning_closes_fd_and_never_retries_or_deletes_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / 'preserve').write_bytes(b'keep')
            fd = os.open(workspace, os.O_RDONLY)
            connection = Mock()
            connection.getsockopt.return_value = CREDENTIALS.pack(1, 0, 0)
            connection.sendmsg.side_effect = lambda packets, _: len(packets[0])
            sock = Mock()
            sock.__enter__ = Mock(return_value=connection)
            sock.__exit__ = Mock(return_value=False)
            identity = SimpleNamespace(uid=1005, gid=1005, name='mano-task-test')
            broker = SimpleNamespace(pw_uid=999, pw_gid=999)
            with patch('mano_broker.task_factory.os.geteuid', return_value=0), \
                 patch('mano_broker.task_factory.sys.platform', 'linux'), \
                 patch('mano_broker.task_factory.human_uid', return_value=1002), \
                 patch('mano_broker.task_factory.allocate_identity', return_value=identity), \
                 patch('mano_broker.task_factory.create_workspace', return_value=(workspace, fd)), \
                 patch('mano_broker.task_factory.pwd.getpwnam', return_value=broker), \
                 patch('mano_broker.task_factory.socket.SO_PASSCRED', 16, create=True), \
                 patch('mano_broker.task_factory.socket.SO_PEERCRED', 17, create=True), \
                 patch('mano_broker.task_factory.socket.socket', return_value=sock), \
                 patch('mano_broker.task_factory.reply', side_effect=TimeoutError('uncertain')):
                with self.assertRaises(TimeoutError):
                    create_task('goal')
            self.assertEqual(connection.sendmsg.call_count, 1)
            self.assertEqual((workspace / 'preserve').read_bytes(), b'keep')
            with self.assertRaises(OSError):
                os.fstat(fd)
