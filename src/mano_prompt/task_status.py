"""Strict read-only task journal client for the protected native human channel."""

from mano_protocol.actions import Capability, identifier

from .approve import rpc
from .intake import parse

ACTION_STATES = {'intent', 'executing', 'done', 'failed', 'unknown'}
APPROVAL_STATES = {'pending', 'approved', 'expired', 'revoked'}


def packet(prompt_id):
    return b'\x01\x07' + identifier(prompt_id).encode('ascii')


def parse_snapshot(value, expected):
    if not isinstance(value, dict) or set(value) != {
            'prompt', 'action_count', 'actions', 'approvals'}:
        raise ValueError('Invalid human task snapshot')
    prompt = parse(value['prompt'], expected)
    count, actions, approvals = value['action_count'], value['actions'], value['approvals']
    if (type(count) is not int or count < 0 or not isinstance(actions, list)
            or len(actions) != min(count, 16) or not isinstance(approvals, list)
            or len(approvals) > 64 or (prompt['task_id'] is None and (count or approvals))):
        raise ValueError('Invalid bounded task journal')
    seen = set()
    for item in actions:
        if not isinstance(item, dict) or set(item) != {
                'action_id', 'capability', 'state', 'effect_verified'}:
            raise ValueError('Unexpected action status fields')
        identifier(item['action_id'])
        Capability(item['capability'])
        if (not isinstance(item['state'], str) or item['state'] not in ACTION_STATES
                or type(item['effect_verified']) is not bool or item['action_id'] in seen
                or (item['effect_verified'] and item['state'] != 'done')):
            raise ValueError('Invalid action state or verification')
        seen.add(item['action_id'])
    seen = set()
    for item in approvals:
        if not isinstance(item, dict) or set(item) != {'approval_id', 'capability', 'state'}:
            raise ValueError('Unexpected approval status fields')
        identifier(item['approval_id'])
        Capability(item['capability'])
        if (not isinstance(item['state'], str) or item['state'] not in APPROVAL_STATES
                or item['approval_id'] in seen):
            raise ValueError('Invalid approval state')
        seen.add(item['approval_id'])
    return dict(prompt=prompt, action_count=count, actions=[dict(a) for a in actions],
                approvals=[dict(a) for a in approvals])


def read_task_status(prompt_id):
    result = rpc(packet(prompt_id))
    if not isinstance(result, dict) or result.get('ok') is not True:
        raise ValueError('Task status unavailable')
    return parse_snapshot(result.get('snapshot'), prompt_id)
