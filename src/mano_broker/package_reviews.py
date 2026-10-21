"""Current catalog-bound installation review; never a grant or apply operation."""

import hashlib
import json
import time

from mano_protocol.actions import ActionRequest, canonical, unique_object
from mano_protocol.packages import digest, result, result_digest

from .package_catalog import load
from .state import Denied
from .terminal_output import read


def review(runtime, body, *, peer):
    state = runtime.state
    if not isinstance(body, dict) or set(body) != {
        'task_id', 'resource_id', 'action_id', 'plan_sha256'
    }:
        raise Denied('Exact owned package forecast review required')
    runtime.live_task(body, peer)
    digest(body['plan_sha256'])
    before = (state.meta('epoch'), state.meta('native_generation'))
    if state.meta('latched'):
        raise Denied('Stop prevents new package installation review')
    captured = read(state, task_id=body['task_id'], action_id=body['action_id'],
                    caller_uid=peer.uid, boot_id=runtime.boot_id)
    if captured is None:
        raise Denied('No durable package forecast')
    metadata, output = captured
    action = state.db.execute('SELECT request_json FROM actions WHERE id=?',
                              (body['action_id'],)).fetchone()
    request = ActionRequest.parse(action['request_json'].encode())
    if (request.capability != 'packages.plan_install'
            or request.resource_id != body['resource_id']
            or metadata['return_code'] != 0 or metadata['reason'] != 'completed'
            or output['stderr']):
        raise Denied('Only a successful package forecast can be reviewed')
    plan = result(json.loads(output['stdout'], object_pairs_hook=unique_object),
                  expected=json.loads(request.args_json))
    if result_digest(plan, expected=json.loads(request.args_json)) != body['plan_sha256']:
        raise Denied('Reviewed forecast digest changed')
    _, catalog = load(plan['catalog_id'])
    if (catalog['status_sha256'] != plan['status_sha256']
            or catalog['expires_at'] != plan['catalog_expires_at']):
        raise Denied('Forecast no longer matches current package inputs')
    now = int(time.time())
    expires = min(now + 60, catalog['expires_at'])
    if expires <= now:
        raise Denied('Package review expired')
    runtime.sync_stop()
    if state.meta('latched') or before != (state.meta('epoch'), state.meta('native_generation')):
        raise Denied('Authority changed during package review')
    # This describes the captured solution and a point-in-time input check.
    # A future apply must take locks, independently re-resolve, and obtain its
    # own exact approval. Neither this digest nor the forecast grant is authority.
    value = dict(
        schema_version='1.0', task_id=body['task_id'], resource_id=body['resource_id'],
        action_id=body['action_id'], boot_id=runtime.boot_id, epoch=before[0],
        native_generation=before[1], plan_sha256=body['plan_sha256'], plan=plan,
        issued_at=now, expires_at=expires, catalog_inputs_current_at_review=True,
        package_locks_held=False, root_resolution_verified=False,
        fresh_apply_approval_required=True, install_authorized=False,
        apply_available=False, current_applicability_verified=False,
        external_effects_reversible=False,
    )
    return value | dict(review_sha256=hashlib.sha256(canonical(value).encode()).hexdigest())
