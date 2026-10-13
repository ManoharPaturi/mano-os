"""Protected human-intent queue; receiving a goal grants no execution authority."""

import secrets

from .protocol import identifier, text
from .state import Denied

MAX_PROMPTS = 256


def public(row):
    return {key: row[key] for key in ('id', 'state', 'task_id')}


class Prompts:
    def __init__(self, state):
        self.state = state

    def submit(self, *, human_uid, request_key, prompt, boot_id):
        if type(human_uid) is not int or human_uid < 1000:
            raise ValueError('Trusted human identity required')
        identifier(request_key)
        text(prompt, 8192)
        with self.state.transaction():
            prior = self.state.db.execute(
                'SELECT * FROM human_prompts WHERE human_uid=? AND request_key=?',
                (human_uid, request_key)).fetchone()
            if prior is not None:
                if prior['prompt'] != prompt or prior['boot_id'] != boot_id:
                    raise Denied('Human prompt idempotency conflict')
                return public(prior)
            count = self.state.db.execute('SELECT count(*) FROM human_prompts').fetchone()[0]
            if count >= MAX_PROMPTS:
                raise Denied('Human prompt lifetime quota exhausted')
            prompt_id = secrets.token_hex(16)
            self.state.db.execute('INSERT INTO human_prompts VALUES(?,?,?,?,?,?,NULL)',
                (prompt_id, human_uid, request_key, prompt, boot_id, 'received'))
            self.state.event(None, 'human-prompt-received', dict(prompt_id=prompt_id,
                                                               human_uid=human_uid))
            return dict(id=prompt_id, state='received', task_id=None)

    def status(self, prompt_id, *, human_uid, boot_id):
        identifier(prompt_id)
        row = self.state.db.execute(
            'SELECT * FROM human_prompts WHERE id=? AND human_uid=? AND boot_id=?',
            (prompt_id, human_uid, boot_id)).fetchone()
        if row is None or type(human_uid) is not int:
            raise Denied('Human prompt unavailable')
        return public(row)

    def claim(self, prompt_id, *, human_uid, boot_id):
        identifier(prompt_id)
        if type(human_uid) is not int or human_uid < 1000:
            raise ValueError('Trusted human identity required')
        with self.state.transaction():
            row = self.state.db.execute(
                'SELECT * FROM human_prompts WHERE id=? AND human_uid=? AND boot_id=?',
                (prompt_id, human_uid, boot_id)).fetchone()
            if row is None or row['state'] != 'received' or self.state.meta('latched'):
                raise Denied('Prompt creation cannot be claimed or retried')
            self.state.db.execute("UPDATE human_prompts SET state='creating_task' WHERE id=?",
                                  (prompt_id,))
            self.state.event(None, 'human-prompt-claimed', dict(prompt_id=prompt_id))
            return dict(id=prompt_id, prompt=row['prompt'])

    def attach(self, prompt_id, task_id, *, human_uid, boot_id):
        identifier(prompt_id)
        identifier(task_id)
        if type(human_uid) is not int or human_uid < 1000:
            raise ValueError('Trusted human identity required')
        with self.state.transaction():
            row = self.state.db.execute(
                'SELECT * FROM human_prompts WHERE id=? AND human_uid=? AND boot_id=?',
                (prompt_id, human_uid, boot_id)).fetchone()
            task = self.state.db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
            if (row is None or row['state'] != 'creating_task' or task is None
                    or self.state.meta('latched')
                    or (task['human_uid'], task['boot_id']) != (human_uid, boot_id)):
                raise Denied('No matching original prompt and provisioned task')
            if self.state.db.execute('SELECT 1 FROM human_prompts WHERE task_id=?',
                                     (task_id,)).fetchone():
                raise Denied('Task already belongs to a prompt')
            self.state.db.execute("UPDATE human_prompts SET state='task_created',task_id=? "
                                  "WHERE id=?",
                                  (task_id, prompt_id))
            self.state.event(None, 'human-prompt-task-attached', dict(prompt_id=prompt_id,
                                                                   task_id=task_id))
            return dict(id=prompt_id, state='task_created', task_id=task_id)

    def uncertain(self, prompt_id, *, human_uid, boot_id):
        identifier(prompt_id)
        if type(human_uid) is not int or human_uid < 1000:
            raise ValueError('Trusted human identity required')
        with self.state.transaction():
            row = self.state.db.execute(
                'SELECT * FROM human_prompts WHERE id=? AND human_uid=? AND boot_id=?',
                (prompt_id, human_uid, boot_id)).fetchone()
            if row is None or row['state'] not in {'creating_task', 'unknown_task_creation'}:
                raise Denied('No uncertain claimed creation')
            self.state.db.execute("UPDATE human_prompts SET state='unknown_task_creation' "
                                  "WHERE id=?",
                                  (prompt_id,))
            self.state.event(None, 'human-prompt-creation-uncertain', dict(prompt_id=prompt_id))
            return dict(id=prompt_id, state='unknown_task_creation', task_id=None)
