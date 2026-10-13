"""Protected human-intent queue; receiving a goal grants no execution authority."""

import json
import secrets
from pathlib import PurePosixPath

from .protocol import canonical, identifier, text
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

    def store_context(self, prompt_id, *, human_uid, managed, boot_id):
        identifier(prompt_id)
        if (type(human_uid) is not int or not isinstance(managed, dict)
                or set(managed) != {'context', 'workspace', 'caller_uid', 'caller_name', 'mode',
                                    'prompt_id'} or managed['prompt_id'] != prompt_id):
            raise ValueError('Expected original managed prompt context')
        context = managed['context']
        if (not isinstance(context, dict)
                or set(context) != {'task_id', 'resource_id', 'operation_key', 'prompt'}):
            raise ValueError('Unexpected task context')
        identifier(context['task_id'])
        identifier(context['resource_id'])
        if context['operation_key'] != prompt_id:
            raise Denied('Prompt operation key changed')
        text(context['prompt'], 8192)
        workspace = PurePosixPath(managed['workspace'])
        if (workspace.parent != PurePosixPath('/var/lib/mano-workspaces')
                or str(workspace) != managed['workspace']):
            raise Denied('Context workspace is outside fixed administrative parent')
        identifier(workspace.name)
        text(managed['caller_name'], 64)
        if (type(managed['caller_uid']) is not int or managed['caller_uid'] < 1000
                or not managed['caller_name'].startswith('mano-task-')
                or managed['mode'] != 'supervised'):
            raise Denied('Context caller/mode mismatch')
        with self.state.transaction():
            row = self.state.db.execute('SELECT p.*,t.caller_uid,t.resource_id '
                'FROM human_prompts p '
                'JOIN tasks t ON p.task_id=t.id WHERE p.id=? AND p.human_uid=? AND p.boot_id=? '
                'AND t.boot_id=?', (prompt_id, human_uid, boot_id, boot_id)).fetchone()
            if (row is None or row['state'] != 'task_created'
                    or row['task_id'] != context['task_id'] or row['prompt'] != context['prompt']
                    or row['caller_uid'] != managed['caller_uid']
                    or row['resource_id'] != context['resource_id']):
                raise Denied('Context does not match original prompt/task')
            encoded = canonical(managed)
            prior = self.state.db.execute('SELECT metadata_json FROM prompt_launch_contexts '
                                         'WHERE prompt_id=?', (prompt_id,)).fetchone()
            if prior is not None:
                if prior[0] != encoded:
                    raise Denied('Original launch context is immutable')
                return
            self.state.db.execute('INSERT INTO prompt_launch_contexts VALUES(?,?)',
                                  (prompt_id, encoded))
            self.state.event(None, 'human-prompt-context-stored', dict(prompt_id=prompt_id))

    def context(self, prompt_id, *, human_uid, boot_id):
        identifier(prompt_id)
        if type(human_uid) is not int:
            raise ValueError('Trusted human identity required')
        row = self.state.db.execute('SELECT c.metadata_json FROM prompt_launch_contexts c '
            'JOIN human_prompts p ON p.id=c.prompt_id JOIN tasks t ON t.id=p.task_id '
            "WHERE p.id=? AND p.human_uid=? AND p.boot_id=? AND t.boot_id=? "
            "AND p.state='task_created'",
            (prompt_id, human_uid, boot_id, boot_id)).fetchone()
        if row is None:
            raise Denied('No original launch context; operator recovery required')
        return json.loads(row[0])
