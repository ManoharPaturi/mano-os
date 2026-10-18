"""One authorized, bounded snapshot of an already pinned workspace inode.

No pathname re-resolution, writing, text interpretation or verification claim.
The read is journaled separately from retrieving its immutable result.
"""

import json
import os
import secrets
import time

from mano_protocol.file_results import MAX_READ as MAX_READ

from .artifacts import MAX_ARTIFACTS, durable_chunk, seal
from .profiles import Profiles
from .protocol import ActionRequest, Capability, canonical, identifier
from .state import Denied


def authority(runtime, action_id, expected, now):
    state = runtime.state
    row = state.db.execute(
        'SELECT a.*,g.revoked,g.epoch,g.expires,g.approved_args_json,t.boot_id,t.caller_uid '
        'FROM actions a JOIN grants g ON a.grant_id=g.id '
        'JOIN tasks t ON a.task_id=t.id WHERE a.id=?', (action_id,)).fetchone()
    if row is None:
        raise Denied('Unknown file read')
    request = ActionRequest.parse(row['request_json'].encode())
    if (row['state'] != expected or request.capability != Capability.READ
            or row['revoked'] or state.meta('latched')
            or row['epoch'] != state.meta('epoch') or now >= row['expires']
            or row['boot_id'] != runtime.boot_id
            or request.args_json != row['approved_args_json']):
        raise Denied('File read authority no longer live')
    Profiles(state).require_grant(row['grant_id'], now=now, boot_id=runtime.boot_id)
    return row, request


def execute(runtime, action_id, *, clock=None):
    clock = clock or time.monotonic
    identifier(action_id)
    state, registry = runtime.state, runtime.registry
    fd = -1
    try:
        row, request = authority(runtime, action_id, 'intent', clock())
        prepared = registry.leases.get(action_id)
        resource = registry.resources.get(request.resource_id)
        if (prepared is None or prepared.closed or prepared.started or resource is None
                or prepared.resource_id != request.resource_id
                or resource.task_id != request.task_id or resource.caller_uid != row['caller_uid']
                or resource.human_uid != state.db.execute(
                    'SELECT human_uid FROM tasks WHERE id=?', (request.task_id,)).fetchone()[0]
                or resource.boot_id != runtime.boot_id or set(prepared.descriptors) != {'target'}):
            raise Denied('Live exact file descriptor lease required')
        if state.db.execute('SELECT count(*) FROM artifacts').fetchone()[0] >= MAX_ARTIFACTS:
            raise Denied('Durable artifact quota exhausted')
        registry.start(state, action_id, now=clock(), boot_id=runtime.boot_id)
        fd, metadata = seal(prepared.descriptors['target'], maximum=MAX_READ)
        data = os.pread(fd, metadata['size'], 0)
        if len(data) != metadata['size']:
            raise Denied('Incomplete immutable file snapshot')
        # Stop/expiry/profile changes during capture prevent publishing its bytes.
        runtime.sync_stop()
        with state.transaction():
            authority(runtime, action_id, 'executing', clock())
            artifact_id = secrets.token_hex(16)
            metadata.update(artifact_id=artifact_id, action_id=action_id,
                task_id=request.task_id, boot_id=runtime.boot_id,
                relative_path=json.loads(request.args_json)['path'], effect_verified=False)
            state.transition(action_id, 'done', exit_code=0)
            state.db.execute('INSERT INTO artifacts VALUES(?,?,?,?)',
                             (artifact_id, action_id, canonical(metadata), data))
            state.event(action_id, 'workspace-read-captured', dict(
                artifact_id=artifact_id, sha256=metadata['sha256'], size=len(data)))
    finally:
        if fd >= 0:
            os.close(fd)
        row = state.db.execute('SELECT state FROM actions WHERE id=?', (action_id,)).fetchone()
        if row and row['state'] in {'intent', 'executing'}:
            state.transition(action_id, 'failed' if row['state'] == 'intent' else 'unknown')
        registry.release(action_id)


def result_chunk(state, *, task_id, action_id, caller_uid, boot_id, offset, length):
    identifier(action_id)
    identifier(task_id)
    rows = state.db.execute(
        'SELECT ar.id,a.request_json,a.state FROM artifacts ar '
        'JOIN actions a ON ar.action_id=a.id JOIN tasks t ON a.task_id=t.id '
        'WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=? LIMIT 2',
        (action_id, task_id, caller_uid, boot_id)).fetchall()
    if (len(rows) != 1 or rows[0]['state'] != 'done'
            or ActionRequest.parse(rows[0]['request_json'].encode()).capability != Capability.READ):
        raise Denied('No unique completed file read for this caller')
    return durable_chunk(state, rows[0]['id'], task_id=task_id, caller_uid=caller_uid,
                         boot_id=boot_id, offset=offset, length=length)
