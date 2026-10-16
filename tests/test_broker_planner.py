import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.ipc import Peer, dispatch
from mano_broker.models import ModelStore
from mano_broker.state import Denied, State
from mano_core.planner import BrokerPlanner
from mano_core.runtime import AgentRuntime
from mano_protocol.actions import canonical


class BrokerPlannerTests(unittest.TestCase):
    def setUp(self):
        from langgraph.checkpoint.memory import InMemorySaver

        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
            resource_id='a' * 32, classification='sensitive', boot_id='boot')
        self.calls = []
        def broker(envelope):
            self.calls.append(envelope)
            # Public dispatcher/journal only; no installed executor or API call.
            return dispatch(self.state, canonical(envelope).encode(),
                            peer=Peer(42, 1004, 1004), now=10, boot_id='boot')
        self.broker = broker
        self.planner = BrokerPlanner(broker, task_id=self.task, resource_id='a' * 32,
            operation_key='build', model='synthetic-snapshot', max_output_tokens=100)
        self.runtime = AgentRuntime(self.planner, broker, checkpointer=InMemorySaver())
        self.input = dict(prompt='build a project', task_id=self.task, resource_id='a' * 32,
                          operation_key='build')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def step(self, state=None):
        return self.runtime.step(state or self.input, thread_id=self.task)

    def approve_model(self):
        row = self.state.db.execute('SELECT id FROM approvals').fetchone()
        queue = Approvals(self.state)
        view = queue.view(row['id'], human_uid=1002)
        queue.approve(row['id'], authenticated_human_uid=1002, nonce=view['nonce'],
            operation_digest=view['operation_digest'], now=10, boot_id='boot')

    def test_disclosure_waits_then_saved_plan_requires_separate_terminal_grant(self):
        first = self.step()
        self.assertEqual(first['status'], 'awaiting_model_grant')
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 0)
        self.approve_model()
        queued = self.step(first)
        self.assertEqual(queued['status'], 'model_queued')
        action_id = self.state.db.execute('SELECT id FROM actions').fetchone()[0]
        store = ModelStore(self.state)
        store.begin(action_id, now=10, boot_id='boot')
        self.assertEqual(self.step(queued)['status'], 'model_running')
        plan = dict(args=dict(argv=['true'], cwd='.', timeout_seconds=1), reason='synthetic plan')
        packet = canonical(dict(object='response', model='synthetic-snapshot', status='completed',
            usage=dict(input_tokens=2, output_tokens=3, total_tokens=5), output=[dict(
                type='function_call', name='propose_terminal', status='completed',
                arguments=canonical(plan))])).encode()
        store.finish(action_id, packet, boot_id='boot')
        terminal = self.step(queued)
        self.assertEqual(terminal['status'], 'awaiting_grant')
        self.assertEqual(terminal['proposal']['capability'], 'terminal.run')
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM grants').fetchone()[0], 1)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 1)
        self.step(terminal)
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 1)

    def test_restart_idempotency_changed_prompt_denial_and_unknown_not_replayed(self):
        self.step()
        self.approve_model()
        self.step()
        action_id = self.state.db.execute('SELECT id FROM actions').fetchone()[0]
        ModelStore(self.state).begin(action_id, now=10, boot_id='boot')
        self.state.recover()
        self.assertEqual(self.step()['status'], 'model_unknown_effect')
        self.assertEqual(self.step()['status'], 'model_unknown_effect')
        self.assertEqual(self.state.db.execute(
            'SELECT count(*) FROM model_attempts').fetchone()[0], 1)
        with self.assertRaises(Denied):
            self.planner('different prompt under original operation key')

    def test_changed_saved_model_binding_is_rejected_before_result_read(self):
        self.step()
        self.approve_model()
        original = self.planner.broker
        def changed(envelope):
            response = original(envelope)
            if envelope['operation'] == 'status':
                response['action']['proposal_digest'] = '0' * 64
            return response
        self.planner.broker = changed
        with self.assertRaises(ValueError):
            self.step()
        self.assertFalse(any(call['operation'] == 'model_result' for call in self.calls))
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM grants').fetchone()[0], 1)
