"""Human-owned mode requests create pending challenges, never permission authority."""

from mano_protocol.profiles import configuration

from .approvals import Approvals
from .prompts import Prompts
from .protocol import identifier
from .state import Denied


def owned_task(state, *, human_uid, prompt_id, boot_id):
    if type(human_uid) is not int or human_uid < 1000:
        raise Denied('Native human identity required')
    prompt = Prompts(state).status(prompt_id, human_uid=human_uid, boot_id=boot_id)
    if prompt['state'] != 'task_created' or prompt['task_id'] is None:
        raise Denied('A provisioned task is required; no implicit creation')
    task = state.db.execute('SELECT * FROM tasks WHERE id=?', (prompt['task_id'],)).fetchone()
    if task is None or (task['human_uid'], task['boot_id']) != (human_uid, boot_id):
        raise Denied('Profile task does not belong to this human and boot')
    return task


def profile_status(state, *, human_uid, prompt_id, now, boot_id):
    from .profiles import Profiles

    with state.transaction():
        task = owned_task(state, human_uid=human_uid, prompt_id=prompt_id, boot_id=boot_id)
        return dict(prompt_id=prompt_id, task_id=task['id'],
                    profile=Profiles(state).status(task, now=now, boot_id=boot_id))


def request_profile(state, *, human_uid, prompt_id, request_key, args, now, boot_id):
    identifier(request_key)
    args = configuration(args)
    with state.transaction():
        task = owned_task(state, human_uid=human_uid, prompt_id=prompt_id, boot_id=boot_id)
        proposal = dict(schema_version='1.0', task_id=task['id'], resource_id=task['resource_id'],
            capability='policy.set_profile', args=args,
            idempotency_key='human-profile:' + request_key,
            reason='Human requested a bounded workspace permission profile')
        approval = Approvals(state).request(proposal, caller_uid=task['caller_uid'],
                                            now=now, boot_id=boot_id)
        return dict(prompt_id=prompt_id, task_id=task['id'], approval=approval)
