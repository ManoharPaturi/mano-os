import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.ipc import Peer, dispatch
from mano_broker.protocol import canonical
from mano_broker.state import State
from mano_core.runtime import AgentRuntime


@unittest.skipUnless(importlib.util.find_spec('langgraph'), 'Optional LangGraph required')
class AgentRuntimeTests(unittest.TestCase):
    def setUp(self):
        from langgraph.checkpoint.memory import InMemorySaver

        self.temp = tempfile.TemporaryDirectory()
        self.journal = State(Path(self.temp.name).resolve() / 'journal')
        self.task = self.journal.create_task(human_uid=1002, caller_uid=1004, mode='auto',
            resource_id='a' * 32, classification='internal', boot_id='boot')
        self.calls = []
        self.plans = []

        def model(prompt):
            self.plans.append(prompt)
            return dict(args=dict(argv=['/usr/bin/true'], cwd='.', timeout_seconds=10),
                        reason='test project')

        def broker(packet):
            self.calls.append(packet['operation'])
            return dispatch(self.journal, canonical(packet).encode(), peer=Peer(42, 1004, 1004),
                            now=10, boot_id='boot')

        self.runtime = AgentRuntime(model, broker, checkpointer=InMemorySaver())
        self.input = dict(prompt='build a project', task_id=self.task, resource_id='a' * 32,
                          operation_key='build-1')

    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()

    def approve(self, pending):
        queue = Approvals(self.journal)
        view = queue.view(pending['approval_id'], human_uid=1002)
        queue.approve(pending['approval_id'], authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'], now=10, boot_id='boot')

    def step(self, state):
        return self.runtime.step(state, thread_id=self.task)

    def test_real_graph_waits_for_grant_and_reconciles_done_and_unknown_without_replay(self):
        pending = self.step(self.input)
        self.assertEqual(pending['status'], 'awaiting_grant')
        saved = self.runtime.graph.get_state(
            {'configurable': {'thread_id': self.task}}
        ).values
        self.assertEqual(saved['approval_id'], pending['approval_id'])
        self.assertEqual(self.journal.db.execute('SELECT count(*) FROM actions').fetchone()[0], 0)
        self.approve(pending)
        queued = self.step(pending)
        self.assertEqual(queued['status'], 'queued')
        action = queued['action_id']
        replay = self.step(pending)
        self.assertEqual(replay['action_id'], action)
        self.assertEqual(self.journal.db.execute('SELECT count(*) FROM actions').fetchone()[0], 1)
        proposals = self.calls.count('propose')
        self.journal.start(action, now=10, boot_id='boot')
        running = self.step(queued)
        self.assertEqual(running['status'], 'running')
        self.journal.transition(action, 'done', exit_code=0)
        done = self.step(running | {'status': 'completed'})
        self.assertEqual(done['status'], 'verifying')
        self.assertEqual(self.calls.count('propose'), proposals)
        self.assertEqual(len(self.plans), 1)
        self.journal.db.execute("UPDATE actions SET state='unknown' WHERE id=?", (action,))
        self.assertEqual(self.step(done)['status'], 'unknown_effect')
        self.assertEqual(self.calls.count('propose'), proposals)

    def test_malicious_model_and_checkpoint_cannot_supply_authority_or_change_scope(self):
        for extra in ('grant_id', 'verified', 'caller_uid', 'env'):
            self.runtime.model = lambda _, field=extra: dict(args={}, reason='x', **{field: True})
            with self.subTest(field=extra), self.assertRaises(ValueError):
                self.step(self.input)
        self.runtime.model = lambda _: dict(args=dict(argv=['true'], cwd='../escape',
            timeout_seconds=10), reason='x')
        with self.assertRaises(ValueError):
            self.step(self.input)
        self.assertEqual(self.calls, [])

    def test_checkpoint_proposal_scope_change_is_rejected_before_broker_call(self):
        pending = self.step(self.input)
        calls = list(self.calls)
        changed = pending | {'proposal': pending['proposal'] | {'task_id': 'b' * 32}}
        with self.assertRaises(ValueError):
            self.step(changed)
        self.assertEqual(self.calls, calls)

    def test_old_verified_action_cannot_complete_a_different_operation_in_same_task(self):
        pending = self.step(self.input)
        self.approve(pending)
        queued = self.step(pending)
        action = queued['action_id']
        self.journal.start(action, now=10, boot_id='boot')
        self.journal.transition(action, 'done', exit_code=0)
        # Simulate an already verified older action in the trusted journal fixture.
        self.journal.db.execute('UPDATE actions SET verified=1 WHERE id=?', (action,))
        forged = queued | dict(operation_key='different-operation',
            proposal=queued['proposal'] | {'idempotency_key': 'different-operation'})
        with self.assertRaisesRegex(ValueError, 'Journal action does not match'):
            self.step(forged)

    def test_typed_read_waits_and_returns_only_verified_custody_reference(self):
        self.runtime.model = lambda _: dict(capability='files.read',
            args=dict(path='notes.txt'), reason='Read notes')
        pending = self.step(self.input)
        self.assertEqual(pending['status'], 'awaiting_grant')
        self.assertEqual(pending['proposal']['capability'], 'files.read')
        self.approve(pending)
        queued = self.step(pending)
        action = queued['action_id']
        self.journal.start(action, now=10, boot_id='boot')
        self.journal.transition(action, 'done', exit_code=0)
        data = b'local data must not become model input' * 250
        meta = dict(artifact_id='c' * 32, action_id=action, task_id=self.task,
            boot_id='boot', relative_path='notes.txt', effect_verified=False, size=len(data),
            sha256=hashlib.sha256(data).hexdigest(), source_device=1, source_inode=2)
        self.journal.db.execute('INSERT INTO artifacts VALUES(?,?,?,?)',
                                (meta['artifact_id'], action, canonical(meta), data))
        ready = self.step(queued)
        self.assertEqual(ready['status'], 'read_ready')
        self.assertEqual(ready['read_result'], meta)
        self.assertNotIn(data.decode(), canonical(ready))
        self.runtime.model = lambda _: self.fail('Replayed result must not invoke model')
        count = self.calls.count('propose')
        replay = self.step(ready | dict(read_result=dict(sha256='forged'), status='completed'))
        self.assertEqual(replay['status'], 'read_ready')
        self.assertEqual(replay['read_result'], meta)
        self.assertEqual(self.calls.count('propose'), count)
        self.journal.db.execute("UPDATE actions SET state='unknown' WHERE id=?", (action,))
        unknown = self.step(replay)
        self.assertEqual(unknown['status'], 'unknown_effect')
        self.assertIsNone(unknown['read_result'])
