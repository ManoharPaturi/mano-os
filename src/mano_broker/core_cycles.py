"""Root-only controller claims; scheduling never grants task execution authority."""

import secrets

from mano_protocol.provider import configuration

from .approvals import clock
from .protocol import canonical, identifier
from .state import Denied

WAITING = {'awaiting_model_grant', 'model_queued', 'model_running', 'awaiting_grant',
           'queued', 'running', 'verifying'}
TERMINAL = {'completed', 'failed', 'model_failed', 'unknown_effect',
            'model_unknown_effect', 'controller_uncertain', 'read_ready'}


class CoreCycles:
    def __init__(self, state):
        self.state = state

    def claim(self, *, human_uid, model, max_output_tokens, now, boot_id):
        clock(now)
        configuration(model, max_output_tokens)
        if type(human_uid) is not int or human_uid < 1000:
            raise Denied('Trusted human identity required')
        encoded = canonical(dict(model=model, max_output_tokens=max_output_tokens))
        with self.state.transaction():
            generation = self.state.meta('native_generation')
            epoch = self.state.meta('epoch')
            if self.state.meta('latched') or generation < 0:
                raise Denied('Controller requires armed native Stop authority')
            if self.state.db.execute("SELECT 1 FROM core_cycles WHERE state='running'").fetchone():
                return None  # An interrupted/uncertain claim is never silently stolen.
            row = self.state.db.execute(
                "SELECT p.id,p.state FROM human_prompts p LEFT JOIN core_cycles c "
                "ON p.id=c.prompt_id WHERE p.human_uid=? AND p.boot_id=? AND "
                "((c.prompt_id IS NULL AND p.state='received') OR "
                "(c.state='waiting' AND p.state='task_created' AND c.model_json=? "
                "AND c.generation=? AND c.epoch=? AND c.updated<=? "
                "AND (c.status NOT IN ('queued','running','verifying') OR EXISTS("
                "SELECT 1 FROM actions a WHERE a.task_id=p.task_id AND a.idempotency_key=p.id "
                "AND ((c.status='queued' AND a.state!='intent') OR "
                "(c.status='running' AND a.state!='executing') OR "
                "(c.status='verifying' AND (a.state!='done' OR a.verified=1))))))) "
                "ORDER BY COALESCE(c.updated,-1),p.rowid LIMIT 1",
                (human_uid, boot_id, encoded, generation, epoch, now - 5)).fetchone()
            if row is None:
                return None
            nonce = secrets.token_hex(32)
            self.state.db.execute('INSERT OR REPLACE INTO core_cycles VALUES(?,?,?,?,?,?,?,?,?)',
                (row['id'], 'running', nonce, encoded, generation, epoch,
                 'claimed', now, human_uid))
            self.state.event(None, 'core-cycle-claimed', dict(prompt_id=row['id']))
            return dict(prompt_id=row['id'], prompt_state=row['state'], nonce=nonce,
                        model=model, max_output_tokens=max_output_tokens)

    def finish(self, *, human_uid, prompt_id, nonce, status, now, boot_id):
        clock(now)
        identifier(prompt_id)
        if (type(human_uid) is not int or human_uid < 1000 or not isinstance(nonce, str)
                or len(nonce) != 64 or status not in WAITING | TERMINAL):
            raise Denied('Invalid controller cycle result')
        with self.state.transaction():
            row = self.state.db.execute(
                'SELECT c.*,p.boot_id,p.state AS prompt_state FROM core_cycles c '
                'JOIN human_prompts p ON p.id=c.prompt_id WHERE c.prompt_id=?',
                (prompt_id,)).fetchone()
            if (row is None or row['state'] != 'running' or row['nonce'] != nonce
                    or row['human_uid'] != human_uid or row['boot_id'] != boot_id
                    or now < row['updated']
                    or (status in WAITING and row['prompt_state'] != 'task_created')
                    or row['generation'] != self.state.meta('native_generation')
                    or row['epoch'] != self.state.meta('epoch') or self.state.meta('latched')):
                raise Denied('Controller result no longer matches original claim')
            state = 'waiting' if status in WAITING else 'terminal'
            self.state.db.execute('UPDATE core_cycles SET state=?,status=?,updated=? '
                                  'WHERE prompt_id=?', (state, status, now, prompt_id))
            self.state.event(None, 'core-cycle-finished', dict(prompt_id=prompt_id, status=status))
