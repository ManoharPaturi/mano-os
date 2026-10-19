"""Bounded publication receipts, distinct from independent current-content verification."""

import re

from .actions import identifier, relative_path, text


def metadata(value, *, task_id, action_id, path):
    if not isinstance(value, dict) or set(value) != {
            'task_id', 'action_id', 'boot_id', 'relative_path', 'publication', 'sha256', 'size',
            'published_device', 'published_inode', 'effect_verified', 'current_content_verified'}:
        raise ValueError('Unexpected file publication fields')
    if (value['task_id'] != identifier(task_id) or value['action_id'] != identifier(action_id)
            or value['relative_path'] != relative_path(path)
            or value['effect_verified'] is not False
            or value['current_content_verified'] is not False
            or value['publication'] not in {'created', 'replace-slot'}
            or type(value['size']) is not int or not 0 <= value['size'] <= 32768
            or not isinstance(value['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['sha256'])
            or any(type(value[k]) is not int or value[k] < 0
                   for k in ('published_device', 'published_inode'))):
        raise ValueError('File publication identity or bounds changed')
    text(value['boot_id'], 128)
    return dict(value)
