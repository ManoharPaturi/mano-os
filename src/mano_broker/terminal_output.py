"""Private durable output custody; no filesystem paths or execution endpoint."""

import hashlib
import json

from mano_protocol.terminal_output import RESULT_LIMIT, STREAM_LIMIT, metadata

from .protocol import ActionRequest, Capability, canonical, identifier
from .state import Denied


def capacity(state, in_flight=0):
    used = state.db.execute('SELECT count(*) FROM terminal_outputs').fetchone()[0]
    if used + in_flight >= RESULT_LIMIT:
        raise Denied('Terminal output lifetime quota exhausted')


def persist(state, action_id, outcome, streams, *, boot_id):
    row = state.db.execute('SELECT a.*,t.boot_id FROM actions a JOIN tasks t ON a.task_id=t.id '
                           'WHERE a.id=?', (identifier(action_id),)).fetchone()
    if (row is None or row['state'] != 'executing' or row['boot_id'] != boot_id
            or ActionRequest.parse(row['request_json'].encode()).capability
            not in {Capability.RUN, Capability.MCP, Capability.PACKAGE}
            or set(streams) != {'stdout', 'stderr'}
            or any(not isinstance(b, bytes) or len(b) > STREAM_LIMIT for b in streams.values())):
        raise Denied('Exact executing terminal action and bounded bytes required')
    capacity(state)
    request = ActionRequest.parse(row['request_json'].encode())
    if request.capability == Capability.PACKAGE and outcome['return_code'] == 0:
        from mano_protocol.actions import unique_object
        from mano_protocol.packages import result

        from .package_catalog import load

        expected = json.loads(request.args_json)
        _, catalog = load(expected['catalog_id'])
        plan = result(json.loads(streams['stdout'],object_pairs_hook=unique_object),
                      expected=expected)
        if (plan['status_sha256'] != catalog['status_sha256']
                or plan['solver'] != catalog['solver']
                or plan['catalog_expires_at'] != catalog['expires_at']
                or plan['free_space_bytes_at_catalog'] != catalog['free_space_bytes']
                or streams['stderr']):
            raise Denied('Package plan differs from approved catalog')
    meta = metadata(dict(task_id=row['task_id'], action_id=action_id, boot_id=boot_id,
        return_code=outcome['return_code'], reason=outcome['reason'],
        output_limit_reached=outcome['reason'] == 'output-limit', effect_verified=False,
        streams={key: dict(size=len(data), sha256=hashlib.sha256(data).hexdigest())
                 for key, data in streams.items()}), task_id=row['task_id'], action_id=action_id)
    with state.transaction():
        state.db.execute('INSERT INTO terminal_outputs VALUES(?,?,?,?)',
            (action_id, canonical(meta), streams['stdout'], streams['stderr']))
        code = meta['return_code']
        state.transition(action_id, 'done' if code == 0 else 'failed', exit_code=code)
        state.event(action_id, 'terminal-output-captured', dict(
            streams=meta['streams'], reason=meta['reason']))  # No source bytes in diagnostics.


def read(state, *, task_id, action_id, caller_uid, boot_id):
    identifier(task_id)
    identifier(action_id)
    if type(caller_uid) is not int:
        raise Denied('Native task identity required')
    action = state.db.execute('SELECT a.* FROM actions a JOIN tasks t ON a.task_id=t.id '
        'WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=?',
        (action_id, task_id, caller_uid, boot_id)).fetchone()
    if (action is None
            or ActionRequest.parse(action['request_json'].encode()).capability
            not in {Capability.RUN, Capability.MCP, Capability.PACKAGE}):
        raise Denied('Terminal output unavailable to this task/caller/boot')
    row = state.db.execute('SELECT * FROM terminal_outputs WHERE action_id=?',
                            (action_id,)).fetchone()
    if row is None:
        return None  # Explicit missing custody, never fabricated empty output.
    meta = metadata(json.loads(row['metadata_json']), task_id=task_id, action_id=action_id)
    if (action['state'] not in {'done', 'failed'} or meta['boot_id'] != boot_id
            or action['exit_code'] != meta['return_code']
            or action['state'] != ('done' if meta['return_code'] == 0 else 'failed')):
        raise Denied('Output no longer matches the authoritative action')
    for name in ('stdout', 'stderr'):
        data = row[name]
        if (len(data) != meta['streams'][name]['size']
                or hashlib.sha256(data).hexdigest() != meta['streams'][name]['sha256']):
            raise Denied('Durable terminal output integrity mismatch')
    return meta, row


def chunk(state, *, task_id, action_id, caller_uid, boot_id, stream, offset, length):
    if (not isinstance(stream, str) or stream not in {'stdout', 'stderr'}
            or type(offset) is not int or offset < 0
            or type(length) is not int or not 1 <= length <= 4096):
        raise Denied('Invalid bounded terminal output range')
    result = read(state, task_id=task_id, action_id=action_id, caller_uid=caller_uid,
                  boot_id=boot_id)
    if result is None:
        raise Denied('Terminal output was not captured')
    meta, row = result
    data = row[stream]
    if offset > len(data):
        raise Denied('Terminal output range unavailable')
    piece = data[offset:offset + length]
    return dict(metadata=meta, data=piece, eof=offset + len(piece) == len(data))
