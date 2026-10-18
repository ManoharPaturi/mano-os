"""Bounded human-owned journal visibility; no grants, arguments or challenge secrets."""

import json

from .approvals import clock, effective_state
from .prompts import Prompts
from .state import Denied

ACTION_LIMIT = 16


def snapshot(state, *, human_uid, prompt_id, boot_id, now):
    clock(now)
    if type(human_uid) is not int or human_uid < 1000:
        raise Denied('Expected native human identity')
    with state.transaction():
        prompt = Prompts(state).status(prompt_id, human_uid=human_uid, boot_id=boot_id)
        result = dict(prompt=prompt, action_count=0, actions=[], approvals=[])
        task_id = prompt['task_id']
        if task_id is None:
            return result
        task = state.db.execute('SELECT human_uid,boot_id FROM tasks WHERE id=?',
                                (task_id,)).fetchone()
        if task is None or (task['human_uid'], task['boot_id']) != (human_uid, boot_id):
            raise Denied('Prompt task does not belong to this human and boot')
        result['action_count'] = state.db.execute(
            'SELECT count(*) FROM actions WHERE task_id=?', (task_id,)).fetchone()[0]
        rows = state.db.execute(
            'SELECT a.id,a.state,a.verified,g.capability FROM actions a '
            'JOIN grants g ON a.grant_id=g.id WHERE a.task_id=? '
            'ORDER BY a.rowid DESC LIMIT ?', (task_id, ACTION_LIMIT)).fetchall()
        if any(row['verified'] not in (0, 1) or (row['verified'] and row['state'] != 'done')
               for row in rows):
            raise Denied('Invalid journal verification state')
        result['actions'] = [dict(action_id=row['id'], capability=row['capability'],
            state=row['state'], effect_verified=bool(row['verified'])) for row in rows]
        rows = state.db.execute(
            'SELECT * FROM approvals WHERE task_id=? ORDER BY rowid DESC LIMIT 65',
            (task_id,)).fetchall()
        if len(rows) > 64:
            raise Denied('Approval lifetime bound exceeded')
        result['approvals'] = [dict(approval_id=row['id'],
            capability=json.loads(row['view_json'])['capability'],
            state=effective_state(state, row, now)) for row in rows]
        return result
