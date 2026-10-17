"""Durable one-dispatch provider jobs. No sockets opened or API calls issued here."""

import json
import secrets

from mano_protocol.actions import MAX_PACKET, canonical
from mano_protocol.provider_handoff import receive_response, validate_binding

from .approvals import clock
from .model_pricing import PricePolicy, begin_priced, finish_priced
from .models import ModelStore
from .state import Denied


class ProviderJobs:
    def __init__(self, state):
        self.state = state

    def original(self, action_id, boot_id):
        action, request = ModelStore(self.state).action(action_id, boot_id)
        job = self.state.db.execute('SELECT * FROM provider_jobs WHERE action_id=?',
                                    (action_id,)).fetchone()
        if job is None or job['request_digest'] != request.digest:
            raise Denied('No original provider job custody')
        binding = json.loads(job['binding_json'])
        validate_binding(binding)
        if (binding['task_id'] != request.task_id or binding['action_id'] != action_id
                or binding['boot_id'] != boot_id or binding['request_sha256'] != request.digest):
            raise Denied('Provider job binding changed')
        return action, request, job, binding

    def prepare(self, action_id, *, policy, now, wall_time, boot_id):
        with self.state.transaction():
            args = begin_priced(self.state, action_id, policy=policy, now=now,
                                wall_time=wall_time, boot_id=boot_id)
            _, request = ModelStore(self.state).action(action_id, boot_id)
            binding = dict(task_id=request.task_id, action_id=action_id, boot_id=boot_id,
                           nonce=secrets.token_hex(32), request_sha256=request.digest)
            validate_binding(binding)
            self.state.db.execute('INSERT INTO provider_jobs VALUES(?,?,?,?)',
                (action_id, request.digest, canonical(binding), 'prepared'))
            self.state.event(action_id, 'provider-job-prepared',
                             dict(request_sha256=request.digest))
            return args

    def claim(self, action_id, *, now, wall_time, boot_id):
        clock(now)
        with self.state.transaction():
            action, request, job, binding = self.original(action_id, boot_id)
            grant = self.state.db.execute('SELECT * FROM grants WHERE id=?',
                                          (request.grant_id,)).fetchone()
            if (action['state'] != 'executing' or job['state'] != 'prepared'
                    or self.state.meta('latched') or grant['revoked']
                    or grant['native_generation'] < 0
                    or grant['epoch'] != self.state.meta('epoch') or now >= grant['expires']):
                raise Denied('Provider job cannot be dispatched or repeated')
            price = self.state.db.execute('SELECT policy_json FROM model_prices WHERE action_id=?',
                                          (action_id,)).fetchone()
            if price is None:
                raise Denied('Original provider price policy missing')
            policy = PricePolicy(**json.loads(price['policy_json']))
            policy.quote(json.loads(request.args_json), wall_time=wall_time)
            packet = canonical(dict(schema_version='1.0', operation='generate',
                body=dict(binding=binding, request=request.body(),
                    native_stop_generation=grant['native_generation'],
                    grant_expires_monotonic=grant['expires'],
                    price_expires_unix=policy.expires_unix))).encode()
            if len(packet) > MAX_PACKET:
                raise Denied('Provider dispatch packet exceeds bound')
            self.state.db.execute("UPDATE provider_jobs SET state='dispatching' WHERE action_id=?",
                                  (action_id,))
            self.state.event(action_id, 'provider-job-dispatch-claimed', {})
            return packet

    def finish(self, action_id, packet, *, binding, boot_id):
        with self.state.transaction():
            action, _, job, original = self.original(action_id, boot_id)
            if (job['state'] != 'dispatching' or action['state'] != 'executing'
                    or binding != original):
                raise Denied('Provider reply does not match the original dispatch')
            result = finish_priced(self.state, action_id, packet, boot_id=boot_id)
            self.state.db.execute("UPDATE provider_jobs SET state='finished' WHERE action_id=?",
                                  (action_id,))
            self.state.event(action_id, 'provider-job-result-custody', {})
            return result

    def uncertain(self, action_id, *, boot_id):
        with self.state.transaction():
            action, _, job, _ = self.original(action_id, boot_id)
            if job['state'] not in {'prepared', 'dispatching'} or action['state'] != 'executing':
                raise Denied('No unresolved original provider job')
            ModelStore(self.state).uncertain(action_id, boot_id=boot_id)
            self.state.db.execute("UPDATE provider_jobs SET state='unknown' WHERE action_id=?",
                                  (action_id,))

    def receive(self, connection, action_id, *, expected_uid, expected_gid, boot_id):
        action, _, job, binding = self.original(action_id, boot_id)
        if job['state'] != 'dispatching' or action['state'] != 'executing':
            raise Denied('No active original provider dispatch')
        try:
            packet = receive_response(connection, binding=binding, expected_uid=expected_uid,
                                      expected_gid=expected_gid)
            return self.finish(action_id, packet, binding=binding, boot_id=boot_id)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            # Never release the reserve or make a second dispatch claim on lost ACK.
            current, _, job, _ = self.original(action_id, boot_id)
            if current['state'] == 'executing' and job['state'] in {'prepared', 'dispatching'}:
                self.uncertain(action_id, boot_id=boot_id)
            raise
