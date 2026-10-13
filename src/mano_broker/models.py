"""Trusted model attempt custody; no HTTP, credentials or automatic retry."""

import hashlib
import json

from mano_protocol.provider import MAX_RESPONSE, decode, response_plan

from .protocol import ActionRequest, Capability, canonical, identifier
from .state import Denied

MAX_ATTEMPTS = 256


class ModelStore:
    def __init__(self, state):
        self.state = state

    def action(self, action_id, boot_id):
        identifier(action_id)
        row = self.state.db.execute('SELECT a.*,t.boot_id FROM actions a JOIN tasks t '
            'ON a.task_id=t.id WHERE a.id=? AND t.boot_id=?', (action_id, boot_id)).fetchone()
        if row is None:
            raise Denied('Model action unavailable')
        request = ActionRequest.parse(row['request_json'].encode())
        if request.capability != Capability.PLAN or request.digest != row['request_digest']:
            raise Denied('No exact model action')
        return row, request

    def begin(self, action_id, *, now, boot_id):
        with self.state.transaction():
            row, request = self.action(action_id, boot_id)
            if self.state.db.execute('SELECT 1 FROM model_attempts WHERE action_id=?',
                                     (action_id,)).fetchone():
                raise Denied('Model attempt cannot be repeated')
            count = self.state.db.execute('SELECT count(*) FROM model_attempts').fetchone()[0]
            if count >= MAX_ATTEMPTS:
                raise Denied('Model attempt lifetime quota exhausted')
            self.state.start(action_id, now=now, boot_id=boot_id)
            self.state.db.execute('INSERT INTO model_attempts VALUES(?,?,NULL,NULL)',
                                  (action_id, request.digest))
            self.state.event(action_id, 'model-attempt-reserved', {})
            return json.loads(request.args_json)

    def finish(self, action_id, packet, *, boot_id):
        with self.state.transaction():
            row, request = self.action(action_id, boot_id)
            attempt = self.state.db.execute('SELECT * FROM model_attempts WHERE action_id=?',
                                           (action_id,)).fetchone()
            grant = self.state.db.execute('SELECT revoked,epoch FROM grants WHERE id=?',
                                         (row['grant_id'],)).fetchone()
            if (row['state'] != 'executing' or attempt is None or attempt['result_json'] is not None
                    or attempt['request_digest'] != request.digest or self.state.meta('latched')
                    or grant is None or grant['revoked']
                    or grant['epoch'] != self.state.meta('epoch')):
                raise Denied('No active original model attempt')
            args = json.loads(request.args_json)
            plan = response_plan(packet, model=args['model'],
                                 max_output_tokens=args['max_output_tokens'])
            value = decode(packet, MAX_RESPONSE)
            result = dict(plan=plan, usage={key: value['usage'][key]
                for key in ('input_tokens', 'output_tokens', 'total_tokens')},
                response_sha256=hashlib.sha256(packet).hexdigest())
            encoded = canonical(result)
            if len(encoded.encode()) > 131072:
                raise Denied('Model result exceeds custody budget')
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            self.state.db.execute('UPDATE model_attempts SET result_json=?,result_sha256=? '
                                  'WHERE action_id=?', (encoded, digest, action_id))
            self.state.transition(action_id, 'done', exit_code=0)
            self.state.event(action_id, 'model-plan-received', dict(result_sha256=digest))
            return result

    def uncertain(self, action_id, *, boot_id):
        with self.state.transaction():
            row, _ = self.action(action_id, boot_id)
            if (row['state'] != 'executing' or not self.state.db.execute(
                    'SELECT 1 FROM model_attempts WHERE action_id=?', (action_id,)).fetchone()):
                raise Denied('No active model attempt')
            self.state.transition(action_id, 'unknown')

    def read(self, action_id, *, task_id, caller_uid, boot_id):
        identifier(task_id)
        row, request = self.action(action_id, boot_id)
        task = self.state.db.execute('SELECT caller_uid FROM tasks WHERE id=?',
                                    (task_id,)).fetchone()
        attempt = self.state.db.execute('SELECT * FROM model_attempts WHERE action_id=?',
                                       (action_id,)).fetchone()
        if (row['task_id'] != task_id or task is None or type(caller_uid) is not int
                or caller_uid != task['caller_uid'] or row['state'] != 'done' or attempt is None
                or attempt['request_digest'] != request.digest or attempt['result_json'] is None):
            raise Denied('Model result unavailable to this caller')
        encoded = attempt['result_json']
        if hashlib.sha256(encoded.encode()).hexdigest() != attempt['result_sha256']:
            raise Denied('Model result custody mismatch')
        return decode(encoded.encode(), 131072)
