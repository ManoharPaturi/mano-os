"""Bounded file byte-custody metadata; never a claim of task verification."""

import re

from .actions import identifier, relative_path, text

MAX_READ = 32768


def metadata(value, *, task_id, action_id, path):
    if not isinstance(value, dict) or set(value) != {
            'artifact_id', 'action_id', 'task_id', 'boot_id', 'relative_path',
            'effect_verified', 'sha256', 'size', 'source_device', 'source_inode'}:
        raise ValueError('Invalid file custody fields')
    for key in ('artifact_id', 'action_id', 'task_id'):
        identifier(value[key])
    text(value['boot_id'], 128)
    relative_path(value['relative_path'])
    if (value['task_id'] != identifier(task_id) or value['action_id'] != identifier(action_id)
            or value['relative_path'] != relative_path(path)
            or value['effect_verified'] is not False
            or type(value['size']) is not int or not 0 <= value['size'] <= MAX_READ
            or not isinstance(value['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['sha256'])
            or any(type(value[k]) is not int or value[k] < 0
                   for k in ('source_device', 'source_inode'))):
        raise ValueError('File custody identity or bounds changed')
    return dict(value)
