"""Bounded terminal byte custody, not semantic verification or model disclosure."""

import re

from .actions import identifier, text

STREAM_LIMIT = 65536
RESULT_LIMIT = 64
REASONS = {'completed', 'timed-out', 'output-limit', 'revoked'}


def metadata(value, *, task_id, action_id):
    if not isinstance(value, dict) or set(value) != {
            'task_id', 'action_id', 'boot_id', 'return_code', 'reason',
            'output_limit_reached', 'effect_verified', 'streams'}:
        raise ValueError('Invalid terminal output metadata')
    if (value['task_id'] != identifier(task_id) or value['action_id'] != identifier(action_id)
            or type(value['return_code']) is not int or not isinstance(value['reason'], str)
            or value['reason'] not in REASONS or value['effect_verified'] is not False
            or type(value['output_limit_reached']) is not bool
            or value['output_limit_reached'] != (value['reason'] == 'output-limit')
            or (value['return_code'] == 0 and value['reason'] != 'completed')
            or not isinstance(value['streams'], dict)
            or set(value['streams']) != {'stdout', 'stderr'}):
        raise ValueError('Invalid terminal output outcome')
    text(value['boot_id'], 128)
    for stream in value['streams'].values():
        if (not isinstance(stream, dict) or set(stream) != {'size', 'sha256'}
                or type(stream['size']) is not int or not 0 <= stream['size'] <= STREAM_LIMIT
                or not isinstance(stream['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', stream['sha256'])):
            raise ValueError('Invalid terminal stream bounds')
    return value
