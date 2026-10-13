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

    def test_uncertain_claim_never_allocates_or_mutates_another_creators_claim(self):
        from mano_broker.task_factory import create_from_prompt

        with patch('mano_broker.task_factory.os.geteuid', return_value=0), \
             patch('mano_broker.task_factory.sys.platform', 'linux'), \
             patch('mano_broker.task_factory.human_uid', return_value=1002), \
             patch('mano_broker.task_factory.control_request',
                   side_effect=[TimeoutError('lost claim'), dict(ok=True)]) as control, \
             patch('mano_broker.task_factory.create_task') as create:
            with self.assertRaises(TimeoutError):
                create_from_prompt('a' * 32)
            create.assert_not_called()
            self.assertEqual([call.args[0] for call in control.call_args_list],
                             ['claim_prompt'])

    def test_lost_claim_race_leaves_winner_able_to_attach_its_task(self):
        from mano_broker.control import dispatch_control
        from mano_broker.ipc import Peer
        from mano_broker.prompts import Prompts
        from mano_broker.protocol import canonical
        from mano_broker.state import Denied, State
        from mano_broker.task_factory import create_from_prompt

        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory).resolve() / 'journal')
            try:
                queue = Prompts(state)
                prompt = queue.submit(human_uid=1002, request_key='a' * 32,
                                      prompt='goal', boot_id='boot')['id']

                def control(operation, body):
                    packet = canonical(dict(schema_version='1.0', operation=operation,
                                            body=body)).encode()
                    return dispatch_control(state, packet, peer=Peer(42, 0, 0), now=10,
                                            boot_id='boot')

                def allocate(goal):
                    self.assertEqual(goal, 'goal')
                    with self.assertRaises(Denied):
                        create_from_prompt(prompt)  # Loser arrives while winner is allocating.
                    self.assertEqual(queue.status(prompt, human_uid=1002, boot_id='boot')
                                     ['state'], 'creating_task')
                    task = state.create_task(human_uid=1002, caller_uid=1005, mode='supervised',
                        resource_id='b' * 32, classification='internal', boot_id='boot')
                    return dict(context=dict(task_id=task, resource_id='b' * 32,
                        operation_key='initial', prompt=goal), caller_uid=1005,
                        caller_name='mano-task-test', mode='supervised',
                        workspace='/var/lib/mano-workspaces/' + 'c' * 32)

                with patch('mano_broker.task_factory.os.geteuid', return_value=0), \
                     patch('mano_broker.task_factory.sys.platform', 'linux'), \
                     patch('mano_broker.task_factory.human_uid', return_value=1002), \
                     patch('mano_broker.task_factory.control_request', side_effect=control), \
                     patch('mano_broker.task_factory.create_task', side_effect=allocate) as create:
                    managed = create_from_prompt(prompt)
                self.assertEqual(create.call_count, 1)
                self.assertEqual(queue.context(prompt, human_uid=1002, boot_id='boot'), managed)
                self.assertEqual(queue.status(prompt, human_uid=1002, boot_id='boot')['state'],
                                 'task_created')
            finally:
                state.close()

    def test_failure_after_acknowledged_claim_marks_only_owned_creation_uncertain(self):
        from mano_broker.task_factory import create_from_prompt

        prompt = 'a' * 32
        with patch('mano_broker.task_factory.os.geteuid', return_value=0), \
             patch('mano_broker.task_factory.sys.platform', 'linux'), \
             patch('mano_broker.task_factory.human_uid', return_value=1002), \
             patch('mano_broker.task_factory.control_request', side_effect=[
                 dict(prompt=dict(id=prompt, prompt='goal')), dict(ok=True)]) as control, \
             patch('mano_broker.task_factory.create_task', side_effect=OSError('failed')) as create:
            with self.assertRaises(OSError):
                create_from_prompt(prompt)
            create.assert_called_once_with('goal')
            self.assertEqual([call.args[0] for call in control.call_args_list],
                             ['claim_prompt', 'uncertain_prompt_creation'])
