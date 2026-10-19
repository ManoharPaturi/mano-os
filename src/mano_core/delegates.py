"""Common approved start/stream/stop API for real pinned coding CLIs.

Delegate text/events are untrusted observations. A successful process/model turn
never establishes task completion or independent artifact verification.
"""

import json
import time

from mano_protocol.actions import ActionRequest, canonical, unique_object
from mano_protocol.delegates import VERSIONS, command, identify

from .pty import PTYSession

DENIALS = ('soft-denied', 'permission denied', 'authentication required', 'not authenticated',
           'missing api key', 'unauthorized', 'requires authentication', 'not logged in',
           'requires approval', 'tool execution denied', 'no credentials', 'login required')


def proposal(*, delegate, operation, task_id, resource_id, key, reason, prompt=None,
             model=None, timeout_seconds=20):
    value = dict(schema_version='1.0', task_id=task_id, resource_id=resource_id,
        capability='terminal.open_pty', args=dict(argv=command(delegate, operation,
            prompt=prompt, model=model), cwd='.', timeout_seconds=timeout_seconds,
            rows=24, columns=80, input_limit_bytes=1), idempotency_key=key, reason=reason)
    ActionRequest.parse(canonical(value | dict(grant_id='0'*32)).encode())
    return value


def classify(name, operation, data, outcome):
    if name not in VERSIONS or not isinstance(data, bytes) or len(data) > 65536:
        raise ValueError('Invalid bounded delegate result')
    result = dict(delegate=name, version=VERSIONS[name], status='unknown',
                  effect_verified=False, output_bytes=len(data), events_untrusted=True)
    if not isinstance(outcome, dict) or outcome.get('reason') != 'exited':
        return result
    code = outcome.get('return_code')
    if type(code) is not int:
        return result
    text = data.decode('utf8', errors='replace')
    if operation in {'version', 'help'}:
        result['status'] = ('inspection' if code == 0 and text.strip()
                            and (operation == 'help' or VERSIONS[name] in text) else 'failed')
        return result
    if any(marker in text.lower() for marker in DENIALS):
        result['status'] = 'denied'
        return result
    terminal = None
    failed = malformed = False
    terminals = 0
    for line in text.splitlines():
        try:
            event = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, TypeError, RecursionError):
            malformed = malformed or bool(line.strip())
            continue  # Mixed diagnostics are untrusted and prevent a success claim.
        if not isinstance(event, dict):
            continue
        if name == 'antigravity' and event.get('event') == 'result':
            value = event.get('result')
            if isinstance(value, dict):
                terminal = value.get('status')
                terminals += 1
        elif name == 'codex':
            if event.get('type') == 'turn.completed':
                terminal = 'SUCCESS'
                terminals += 1
            elif event.get('type') in {'turn.failed', 'error'}:
                failed = True
    if code != 0 or failed or terminal in {'ERROR', 'CANCELED', 'INTERRUPTED', 'INVALID'}:
        result['status'] = 'failed'
    elif terminal == 'SUCCESS' and terminals == 1 and not malformed:
        result['status'] = 'completed-unverified'
    return result


class CodingDelegate:
    def __init__(self, session, *, name, operation):
        self.session, self.name, self.operation = session, name, operation
        self.pending = bytearray()
        self.last = None
        self.started = False
        self.next_read = 0.0

    @classmethod
    def open(cls, client, *, proposal, grant_id):
        name = identify(proposal['args']['argv'])
        if name is None:
            raise ValueError('Pinned delegate proposal required')
        tail = proposal['args']['argv'][1:]
        operation = 'version' if tail == ['--version'] else (
            'help' if tail == ['--help'] else 'run')
        session = PTYSession.open(client, proposal=proposal, grant_id=grant_id)
        return cls(session, name=name, operation=operation)

    def read(self):
        remaining = self.next_read - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        self.next_read = time.monotonic() + 0.25
        if not self.started:
            reply = self.session.client(dict(schema_version='1.0', operation='status', body=dict(
                task_id=self.session.task_id, action_id=self.session.action_id)))
            action = reply.get('action', {})
            if (reply.get('ok') is not True or action.get('id') != self.session.action_id
                    or action.get('task_id') != self.session.task_id):
                raise ValueError('Unbound delegate process status')
            if action.get('state') == 'intent':
                return dict(events=[], eof=False, process_state='intent')
            self.started = True
        observed = self.session.read()
        self.last = observed
        self.pending.extend(observed['data'])
        events = []
        while b'\n' in self.pending or (observed['eof'] and self.pending):
            if b'\n' in self.pending:
                line, _, rest = self.pending.partition(b'\n')
                self.pending = bytearray(rest)
            else:
                line, self.pending = self.pending, bytearray()
            try:
                value = json.loads(line, object_pairs_hook=unique_object)
                kind = 'event' if isinstance(value, dict) else 'diagnostic'
            except (ValueError, TypeError, RecursionError):
                value, kind = bytes(line).decode('utf8', errors='replace'), 'diagnostic'
            events.append(dict(kind=kind, value=value, untrusted=True))
        return dict(events=events, eof=observed['eof'], process_state=observed['state'])

    def result(self):
        if self.last is None or not self.last['eof']:
            raise ValueError('Delegate result is not yet complete')
        return classify(self.name, self.operation, bytes(self.session.output), self.last['outcome'])

    def stop(self, *, key):
        return self.session.close(key=key)
