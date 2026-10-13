"""Trusted, predeclared exact-file predicate; no model-reported success accepted."""

import hashlib
import json
import re

from .approvals import Approvals, clock
from .artifacts import MAX_BYTES
from .protocol import identifier, relative_path
from .state import Denied


def declare(state, approval_id, *, path, sha256, size, now, boot_id):
    identifier(approval_id)
    clock(now)
    relative_path(path)
    if (not isinstance(sha256, str) or not re.fullmatch('[0-9a-f]{64}', sha256)
            or type(size) is not int or not 0 <= size <= MAX_BYTES):
        raise ValueError('Invalid exact-file expectation')
    with state.transaction():
        queue = Approvals(state)
        approval = state.db.execute('SELECT * FROM approvals WHERE id=?',
                                    (approval_id,)).fetchone()
        if approval is None:
            raise Denied('Original pending approval required')
        view = queue.view(approval_id, human_uid=json.loads(
            approval['view_json'])['human_uid'])
        if (approval['state'] != 'pending' or state.meta('latched')
                or view['epoch'] != state.meta('epoch') or now >= view['expires']
                or view['boot_id'] != boot_id or view['capability'] != 'terminal.run'):
            raise Denied('Expectation must precede current live approval')
        values = (approval_id, path, sha256, size, boot_id, view['epoch'])
        prior = state.db.execute('SELECT * FROM artifact_contracts WHERE approval_id=?',
                                 (approval_id,)).fetchone()
        if prior is not None:
            if tuple(prior) != values:
                raise Denied('Original expectation is immutable')
            return
        if state.db.execute('SELECT count(*) FROM artifact_contracts').fetchone()[0] >= 64:
            raise Denied('Expectation quota exhausted')
        state.db.execute('INSERT INTO artifact_contracts VALUES(?,?,?,?,?,?)', values)
        state.event(None, 'exact-file-expectation-declared', dict(
            approval_id=approval_id, sha256=sha256, size=size))


def check(state, action_id, artifact_id, *, boot_id):
    identifier(action_id)
    identifier(artifact_id)
    with state.transaction():
        row = state.db.execute(
            'SELECT c.*,ar.metadata_json,ar.data,a.state,a.verified,t.boot_id AS task_boot '
            'FROM actions a JOIN approvals ap ON a.grant_id=ap.grant_id AND a.task_id=ap.task_id '
            'JOIN artifact_contracts c ON c.approval_id=ap.id '
            'JOIN artifacts ar ON ar.action_id=a.id '
            'JOIN tasks t ON t.id=a.task_id WHERE a.id=? AND ar.id=?',
            (action_id, artifact_id)).fetchone()
        if (row is None or row['state'] != 'done' or row['verified']
                or state.meta('latched') or row['epoch'] != state.meta('epoch')
                or row['boot_id'] != boot_id or row['task_boot'] != boot_id):
            raise Denied('No current completed action and original expectation')
        metadata = json.loads(row['metadata_json'])
        if (metadata.get('relative_path') != row['path'] or len(row['data']) != row['size']
                or metadata.get('sha256') != row['sha256']
                or hashlib.sha256(row['data']).hexdigest() != row['sha256']):
            raise Denied('Declared exact-file predicate failed')
        evidence = dict(artifact_id=artifact_id, sha256=row['sha256'])
        state.record_verification(action_id, checked_artifacts=[evidence])
        state.event(action_id, 'exact-file-predicate-passed', dict(
            approval_id=row['approval_id'], artifact_id=artifact_id, predicate='exact-file-v1'))
        return dict(action_id=action_id, verified=True, predicate='exact-file-v1')
