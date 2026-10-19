"""One bounded LangGraph cycle; no shell, grant creation or verification authority."""

import hashlib
from typing import TypedDict

from mano_protocol.actions import ActionRequest, canonical, identifier, text
from mano_protocol.plans import EXECUTABLE
from mano_protocol.plans import proposal as make_proposal

from .broker import file_write_result, read_file_result, terminal_output
from .planner import PlanningPending


class TaskState(TypedDict, total=False):
    prompt: str
    task_id: str
    resource_id: str
    operation_key: str
    proposal: dict
    approval_id: str
    action_id: str
    status: str
    read_result: dict | None
    terminal_output: dict | None
    write_result: dict | None


class AgentRuntime:
    def __init__(self, model, broker, *, checkpointer=None):
        from langgraph.graph import END, START, StateGraph

        self.model, self.broker = model, broker
        graph = StateGraph(TaskState)
        graph.add_node('cycle', self.cycle)
        graph.add_edge(START, 'cycle')
        graph.add_edge('cycle', END)
        self.graph = graph.compile(checkpointer=checkpointer)

    def request(self, operation, body):
        result = self.broker(dict(schema_version='1.0', operation=operation, body=body))
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise ValueError('Broker denied agent request')
        return result

    def cycle(self, state):
        identifier(state['task_id'])
        identifier(state['resource_id'])
        text(state['operation_key'], 128)
        text(state['prompt'], 8192)
        proposal = state.get('proposal')
        if proposal is None:
            # Model receives the human prompt only; IDs/grants/UIDs are never supplied.
            try:
                plan = self.model(state['prompt'])
            except PlanningPending as pending:
                return dict(status=pending.status)
            proposal = make_proposal(plan, state)
        # Validate both initial and checkpointed proposals with the broker schema.
        parsed = ActionRequest.parse(canonical(proposal | {'grant_id': '0' * 32}).encode())
        if (parsed.task_id != state['task_id'] or parsed.resource_id != state['resource_id']
                or parsed.idempotency_key != state['operation_key']
                or parsed.capability not in EXECUTABLE or 'grant_id' in proposal):
            raise ValueError('Checkpoint proposal changed task scope')
        update = dict(proposal=proposal, read_result=None, terminal_output=None, write_result=None)
        action_id = state.get('action_id')
        if action_id is None:
            approval_id = state.get('approval_id')
            if approval_id is None:
                pending = self.request('request_approval', proposal)['approval']
                approval_id = identifier(pending['approval_id'])
            update['approval_id'] = approval_id
            pending = self.request('approval_status', {'approval_id': approval_id})['approval']
            if pending['state'] != 'approved':
                update['status'] = ('awaiting_grant' if pending['state'] == 'pending'
                                    else 'failed')
                return update
            grant_id = identifier(pending['grant_id'])
            action = self.request('propose', proposal | {'grant_id': grant_id})['action']
            action_id = identifier(action['id'])
            update['action_id'] = action_id
        # Always query the broker, even if a checkpoint previously claimed completion.
        action = self.request('status', dict(task_id=state['task_id'],
                                             action_id=action_id))['action']
        expected = hashlib.sha256(canonical(proposal).encode()).hexdigest()
        if (action.get('proposal_digest') != expected or action.get('id') != action_id
                or action.get('task_id') != state['task_id']):
            raise ValueError('Journal action does not match the original proposal')
        status = action['state']
        if parsed.capability == 'terminal.run' and status in {'done', 'failed'}:
            update['terminal_output'] = terminal_output(self.broker,
                task_id=state['task_id'], action_id=action_id)
        if status == 'done':
            if parsed.capability == 'files.read':
                captured = read_file_result(self.broker, task_id=state['task_id'],
                    action_id=action_id, path=proposal['args']['path'])
                # Keep only a custody reference in checkpoint/stdout, never source bytes.
                update.update(status='read_ready', read_result=captured['metadata'])
            elif parsed.capability == 'files.write':
                receipt = file_write_result(self.broker, task_id=state['task_id'],
                    action_id=action_id, path=proposal['args']['path'])
                if receipt is None:
                    raise ValueError('Completed write has no publication receipt')
                update.update(status='write_published', write_result=receipt)
            else:
                update['status'] = 'completed' if action['verified'] else 'verifying'
        elif status == 'unknown':
            update['status'] = 'unknown_effect'
        elif status == 'failed':
            update['status'] = 'failed'
        elif status in {'intent', 'executing'}:
            update['status'] = 'queued' if status == 'intent' else 'running'
        else:
            raise ValueError('Unexpected broker effect state')
        return update

    def step(self, state, *, thread_id):
        text(thread_id, 128)
        return self.graph.invoke(state, config={'configurable': {'thread_id': thread_id},
                                                'recursion_limit': 4})
