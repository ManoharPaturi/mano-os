"""Read-only human prompt intake state; no execution or approval authority."""

from mano_protocol.actions import identifier

from .approve import rpc
from .submit import status_packet

LABELS = {
    'received': 'Request queued',
    'creating_task': 'Preparing workspace',
    'task_created': 'Workspace ready; execution status is unavailable here',
    'unknown_task_creation': 'Workspace creation uncertain; operator review required',
}


def parse(value, expected=None):
    if not isinstance(value, dict) or set(value) != {'id', 'state', 'task_id'}:
        raise ValueError('Invalid prompt intake status')
    identifier(value['id'])
    if expected is not None and value['id'] != expected:
        raise ValueError('Prompt status identity changed')
    if not isinstance(value['state'], str) or value['state'] not in LABELS:
        raise ValueError('Unknown prompt intake state')
    if value['state'] == 'task_created':
        identifier(value['task_id'])
    elif value['task_id'] is not None:
        raise ValueError('Unexpected prompt task identity')
    return dict(value)


def read_status(prompt_id):
    identifier(prompt_id)
    result = rpc(status_packet(prompt_id))
    if not isinstance(result, dict) or result.get('ok') is not True:
        raise ValueError('Prompt status unavailable')
    return parse(result.get('prompt'), prompt_id)


class Intake:
    def __init__(self):
        self.current = None
        self.revision = 0
        self.activity = None

    def select(self, result):
        value = parse(result)
        self.revision += 1
        self.current = value
        self.activity = None

    def token(self):
        if self.current is None:
            raise ValueError('No acknowledged request selected')
        return self.revision, self.current['id']

    def update(self, token, result):
        if token != self.token():
            return False  # A slow reply cannot replace a newer acknowledged request.
        self.current = parse(result, token[1])
        self.activity = None
        return True

    def update_snapshot(self, token, result):
        from .task_status import parse_snapshot

        if token != self.token():
            return False
        value = parse_snapshot(result, token[1])
        if self.current['task_id'] is not None and (
                value['prompt']['task_id'] != self.current['task_id']):
            raise ValueError('Acknowledged task identity changed')
        self.current = value['prompt']
        self.activity = value
        return True

    def display(self):
        value = self.current
        if value is None:
            return ''
        lines = [LABELS[value['state']], 'Request: ' + value['id']]
        if value['task_id'] is not None:
            lines.append('Task: ' + value['task_id'])
        if self.activity is not None:
            if value['task_id'] is not None:
                lines[0] = 'Workspace ready; journal status below'
            actions = self.activity['actions']
            lines.append(f"Recent actions: {len(actions)} of {self.activity['action_count']}"
                         ' (newest first)')
            for item in actions:
                verified = 'effect verified' if item['effect_verified'] else 'effect not verified'
                lines.append(f"{item['action_id']} · {item['capability']} · "
                             f"{item['state']} · {verified}")
            lines.append('Approval records (review pending IDs in the trusted terminal):')
            for item in self.activity['approvals']:
                lines.append(f"{item['approval_id']} · {item['capability']} · {item['state']}")
        return '\n'.join(lines)
