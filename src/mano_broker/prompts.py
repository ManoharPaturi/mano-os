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
