"""Broker-backed planning: no provider key, direct egress, or execution authority."""

import hashlib

from mano_protocol.actions import ActionRequest, canonical, identifier, text
from mano_protocol.provider import configuration

from .broker import read_model_result


class PlanningPending(Exception):
    def __init__(self, status):
        if status not in {'awaiting_model_grant', 'model_queued', 'model_running',
                          'model_unknown_effect', 'model_failed'}:
            raise ValueError('Invalid model planning state')
        self.status = status
        super().__init__(status)


class BrokerPlanner:
    def __init__(self, broker, *, task_id, resource_id, operation_key, model, max_output_tokens):
        self.broker = broker
        self.task_id, self.resource_id = identifier(task_id), identifier(resource_id)
        text(operation_key, 128)
        configuration(model, max_output_tokens)
        self.model, self.max_output_tokens = model, max_output_tokens
        self.key = 'model-' + hashlib.sha256(canonical(dict(task_id=task_id,
            resource_id=resource_id, operation_key=operation_key)).encode()).hexdigest()

    def request(self, operation, body):
        response = self.broker(dict(schema_version='1.0', operation=operation, body=body))
        if (not isinstance(response, dict) or response.get('schema_version') != '1.0'
                or response.get('ok') is not True):
            raise ValueError('Broker denied model planning request')
        return response

    def __call__(self, prompt):
        text(prompt, 8192)
        proposal = dict(schema_version='1.0', task_id=self.task_id, resource_id=self.resource_id,
            capability='model.plan', args=dict(provider='openai', model=self.model, prompt=prompt,
                max_output_tokens=self.max_output_tokens), idempotency_key=self.key,
            reason='Disclose this exact prompt for one bounded model plan')
        pending = self.request('request_approval', proposal)['approval']
        approval_id = identifier(pending['approval_id'])
        approval = self.request('approval_status', dict(approval_id=approval_id))['approval']
        if approval['state'] != 'approved':
            raise PlanningPending('awaiting_model_grant' if approval['state'] == 'pending'
                                  else 'model_failed')
        grant_id = identifier(approval['grant_id'])
        action = self.request('propose', proposal | {'grant_id': grant_id})['action']
        action_id = identifier(action['id'])
        action = self.request('status', dict(task_id=self.task_id, action_id=action_id))['action']
        digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
        if (action.get('id') != action_id or action.get('task_id') != self.task_id
                or action.get('proposal_digest') != digest):
            raise ValueError('Saved model action differs from original disclosure')
        statuses = {'intent': 'model_queued', 'executing': 'model_running',
                    'unknown': 'model_unknown_effect', 'failed': 'model_failed'}
        if action['state'] in statuses:
            raise PlanningPending(statuses[action['state']])
        if action['state'] != 'done':
            raise ValueError('Unexpected model action state')
        result = read_model_result(self.broker, task_id=self.task_id, action_id=action_id)
        plan = result['plan']
        if not isinstance(plan, dict) or set(plan) != {'args', 'reason'}:
            raise ValueError('Invalid saved terminal proposal')
        ActionRequest.parse(canonical(dict(schema_version='1.0', task_id=self.task_id,
            resource_id=self.resource_id, grant_id='0' * 32, capability='terminal.run',
            args=plan['args'], reason=plan['reason'], idempotency_key='plan-validation')).encode())
        return plan
