"""Fresh native approval and one-shot scheduling for exact system package plans."""

import json
import os
import pwd
import select
import socket
import time

from mano_protocol.actions import ActionRequest, canonical, identifier, unique_object
from mano_protocol.packages import apply_arguments, result, result_digest
from mano_protocol.transport import CREDENTIALS, Peer, reply

from .package_catalog import load
from .state import Denied
from .terminal_output import read

SOCKET = '/run/mano-package-apply/request.sock'


def validate(state, request, *, caller_uid, boot_id):
    if request.capability != 'packages.apply_install':
        return None
    args = apply_arguments(json.loads(request.args_json))
    task = state.db.execute('SELECT * FROM tasks WHERE id=?', (request.task_id,)).fetchone()
    if (task is None or task['caller_uid'] != caller_uid or task['boot_id'] != boot_id
            or task['resource_id'] != request.resource_id):
        raise Denied('Current owned package apply task required')
    captured = read(state, task_id=request.task_id, action_id=args['forecast_action_id'],
                    caller_uid=caller_uid, boot_id=boot_id)
    if captured is None:
        raise Denied('No durable owned package forecast')
    metadata, output = captured
    original = state.db.execute('SELECT request_json FROM actions WHERE id=?',
                                (args['forecast_action_id'],)).fetchone()
    forecast = ActionRequest.parse(original['request_json'].encode())
    if (forecast.capability != 'packages.plan_install'
            or forecast.resource_id != request.resource_id
            or metadata['return_code'] != 0 or metadata['reason'] != 'completed'
            or output['stderr']):
        raise Denied('Only a successful exact forecast can be applied')
    expected = json.loads(forecast.args_json)
    plan = result(json.loads(output['stdout'], object_pairs_hook=unique_object), expected=expected)
    if result_digest(plan, expected=expected) != args['plan_sha256']:
        raise Denied('Package apply forecast digest changed')
    _, catalog = load(plan['catalog_id'])
    if (plan['status_sha256'] != catalog['status_sha256']
            or plan['catalog_expires_at'] != catalog['expires_at']):
        raise Denied('Package inputs changed; request a fresh forecast and approval')
    return plan


def approval_scope(plan):
    return dict(plan=plan, plan_sha256=result_digest(plan, expected={key: plan[key]
                for key in ('names', 'catalog_id')}), system_root_operation=True,
                network_sources=['https://deb.debian.org', 'https://security.debian.org'],
                download_byte_limit=plan['download_bytes'], maintainer_scripts=True,
                maintainer_script_network=False, external_effects_reversible=False,
                conffile_policy='preserve-existing', peak_space_bytes=None,
                checkpoint_required=True, native_stop_required=True,
                system_service_configuration_changes_allowed=False,
                profile_auto_approval_allowed=False,
                limits=dict(memory_bytes=512*1024**2, pids=64, cpu_percent=50,
                            maximum_runtime_seconds=60))


class ApplyWorker:
    def __init__(self, runtime):
        self.runtime = runtime
        self.pending = {}

    def launch(self, action_id):
        runtime, state = self.runtime, self.runtime.state
        if self.pending:
            raise Denied('Only one system package transaction may be active')
        row = state.db.execute('SELECT a.*,g.expires,g.native_generation,t.caller_uid '
            'FROM actions a JOIN grants g ON a.grant_id=g.id JOIN tasks t ON a.task_id=t.id '
            'WHERE a.id=?', (action_id,)).fetchone()
        request = ActionRequest.parse(row['request_json'].encode())
        plan = validate(state, request, caller_uid=row['caller_uid'], boot_id=runtime.boot_id)
        broker = pwd.getpwnam('mano-broker')
        if os.geteuid() != broker.pw_uid or broker.pw_uid == 0:
            raise Denied('Separate trusted Broker identity required')
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        started = False
        try:
            connection.setblocking(False)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.connect(SOCKET)
            creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
            if creator.uid != 0 or creator.gid != 0 or creator.pid <= 0:
                raise Denied('Package helper listener is not Root activated')
            runtime.registry.start(state, action_id, now=time.monotonic(), boot_id=runtime.boot_id)
            started = True
            packet = canonical(dict(action_id=action_id, request=request.body(), plan=plan,
                boot_id=runtime.boot_id, native_generation=row['native_generation'],
                expires=row['expires'])).encode()
            if len(packet) > 65536 or connection.send(packet) != len(packet):
                raise Denied('Package dispatch incomplete; outcome uncertain')
            self.pending[action_id] = dict(connection=connection, request=request,
                expires=row['expires'], generation=row['native_generation'])
        except BaseException:
            connection.close()
            if started:
                state.transition(action_id, 'unknown')
            else:
                state.transition(action_id, 'failed')
            runtime.registry.release(action_id)
            raise

    def poll(self, action_id):
        from mano_protocol.stop_state import snapshot

        state, pending = self.runtime.state, self.pending[action_id]
        connection = pending['connection']
        try:
            native = snapshot()
            grant = state.db.execute('SELECT revoked FROM grants WHERE id=?',
                                    (pending['request'].grant_id,)).fetchone()
            if (grant is None or grant['revoked'] or state.meta('latched') or native.latched
                    or native.generation != pending['generation']
                    or time.monotonic() >= pending['expires']):
                raise Denied('Package result authority expired or stopped')
            if not select.select([connection], [], [], 0)[0]:
                return
            _, value = reply(connection)
            request = pending['request']
            if (value.get('ok') is not True or value.get('package_children_drained') is not True
                    or value.get('action_id') != action_id
                    or value.get('request_sha256') != request.digest
                    or value.get('outcome', {}).get('state') != 'postconditions-verified'
                    or value['outcome']['attempt_id'] != action_id
                    or value['outcome']['request_sha256'] != request.digest
                    or value['outcome']['observed_boot_id'] != self.runtime.boot_id
                    or value['outcome']['automatic_replay_allowed'] is not False
                    or value['outcome']['plan_sha256']
                    != json.loads(request.args_json)['plan_sha256']):
                raise Denied('No authenticated exact package postcondition result')
            state.event(action_id, 'package-postconditions-verified', dict(
                outcome=value['outcome'], checkpoint=value['checkpoint'],
                catalog_id=value['catalog_id'], log_sha256=value['log_sha256'],
                boundary=value['boundary'], acquisition=value['acquisition']))
            state.transition(action_id, 'done', exit_code=0)
        except BaseException:
            row = state.db.execute('SELECT state FROM actions WHERE id=?', (action_id,)).fetchone()
            if row['state'] == 'executing':
                state.transition(action_id, 'unknown')
            raise
        finally:
            # Preserve a live job only if no packet/terminal condition was observed.
            if state.db.execute('SELECT state FROM actions WHERE id=?',
                                (action_id,)).fetchone()['state'] != 'executing':
                connection.close()
                self.pending.pop(action_id)
                self.runtime.registry.release(action_id)

    def close(self):
        for action_id, pending in list(self.pending.items()):
            pending['connection'].close()
            row = self.runtime.state.db.execute('SELECT state FROM actions WHERE id=?',
                                               (action_id,)).fetchone()
            if row['state'] == 'executing':
                self.runtime.state.transition(action_id, 'unknown')
            self.runtime.registry.release(action_id)
        self.pending.clear()


def result_for(state, body, *, caller_uid, boot_id):
    if not isinstance(body, dict) or set(body) != {'task_id', 'action_id'}:
        raise Denied('Exact package result scope required')
    identifier(body['task_id'])
    identifier(body['action_id'])
    row = state.db.execute('SELECT a.* FROM actions a JOIN tasks t ON a.task_id=t.id '
        'WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=?',
        (body['action_id'], body['task_id'], caller_uid, boot_id)).fetchone()
    if row is None or json.loads(row['request_json'])['capability'] != 'packages.apply_install':
        raise Denied('No owned package apply result')
    receipt = state.db.execute("SELECT details_json FROM events WHERE action_id=? "
        "AND event='package-postconditions-verified' ORDER BY sequence DESC LIMIT 1",
        (body['action_id'],)).fetchone()
    return dict(state=row['state'], receipt=None if receipt is None else json.loads(receipt[0]))
