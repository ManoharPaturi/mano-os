"""Trusted operator launches only the fixed unprivileged core entry point."""

import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

from mano_protocol.actions import canonical, identifier, text, unique_object

from .stop_state import snapshot
from .task_factory import control_request, create_from_prompt, human_uid
from .workspaces import BASE

CORE_PYTHON = '/usr/local/lib/mano-core/bin/python'


def command(managed):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise PermissionError('Trusted Linux operator required')
    if (not isinstance(managed, dict) or set(managed) - {'context', 'workspace', 'caller_uid',
            'caller_name', 'mode', 'prompt_id'} or managed.get('mode') != 'supervised'):
        raise ValueError('Expected trusted managed task metadata')
    context = managed['context']
    if set(context) != {'task_id', 'resource_id', 'operation_key', 'prompt'}:
        raise ValueError('Unknown managed task context')
    identifier(context['task_id'])
    identifier(context['resource_id'])
    text(context['operation_key'], 128)
    text(context['prompt'], 8192)
    uid = managed['caller_uid']
    if type(uid) is not int or uid < 1000:
        raise ValueError('Unprivileged managed identity required')
    account = pwd.getpwuid(uid)
    if (account.pw_name != managed['caller_name'] or not account.pw_name.startswith('mano-task-')
            or account.pw_gid <= 0 or account.pw_shell != '/usr/sbin/nologin'
            or account.pw_dir != '/nonexistent'):
        raise ValueError('Managed identity policy mismatch')
    workspace = Path(managed['workspace'])
    if workspace.parent != BASE or not re.fullmatch('[0-9a-f]{32}', workspace.name):
        raise ValueError('Fixed administrative workspace required')
    for parent in workspace.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted workspace ancestor')
    info = workspace.lstat()
    broker = pwd.getpwnam('mano-broker')
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != broker.pw_uid
            or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) != 0o2770):
        raise ValueError('Workspace ownership/scope mismatch')
    return ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
        '--unit=mano-agent-step-' + str(time.monotonic_ns()), '--uid=' + account.pw_name,
        '--slice=mano-core.slice', '--property=MemoryMax=256M', '--property=TasksMax=32',
        '--property=CPUQuota=50%', '--property=RuntimeMaxSec=8', '--property=TimeoutStopSec=1',
        '--property=LimitNOFILE=128', '--property=SystemCallArchitectures=native',
        '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=',
        '--property=AmbientCapabilities=', '--property=ProtectSystem=strict',
        '--property=ReadWritePaths=' + str(workspace), '--property=ProtectHome=yes',
        '--property=PrivateTmp=yes', '--property=RestrictNamespaces=yes',
        '--property=RestrictAddressFamilies=AF_UNIX', '--property=SystemCallFilter=@system-service',
        '--property=SystemCallErrorNumber=EPERM', '--property=MemoryDenyWriteExecute=yes',
        'env', 'PYTHONPATH=/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE=1', CORE_PYTHON,
        '-m', 'mano_core.cli', '--mock', '--checkpoint-directory', str(workspace / '.mano-agent')]


def run_mock_step(managed, plan):
    argv = command(managed)
    before = snapshot()
    if before.latched:
        raise ValueError('Native Stop is latched')
    if not isinstance(plan, dict) or set(plan) != {'args', 'reason'}:
        raise ValueError('Explicit mock plan required')
    payload = canonical(dict(context=managed['context'], plan=plan))
    if len(payload.encode()) > 65536:
        raise ValueError('Core input exceeds packet budget')
    result = subprocess.run(argv, input=payload, text=True, capture_output=True,
                            timeout=10, check=False)
    after = snapshot()
    if after.latched or after.generation != before.generation:
        raise ValueError('Stop changed during core execution; reconcile before continuation')
    if result.returncode != 0:
        raise ValueError('Core cycle failed; no implicit retry')
    value = json.loads(result.stdout, object_pairs_hook=unique_object)
    if value.get('ok') is not True:
        raise ValueError('Core did not return a journal-reconciled result')
    task = value['task']
    if any(task.get(key) != expected for key, expected in managed['context'].items()):
        raise ValueError('Core returned different task context')
    action_id = task.get('action_id')
    if action_id is None:
        task['status'] = 'awaiting_grant'  # No completion authority in core stdout.
        return task
    identifier(action_id)
    action = control_request('inspect_action', dict(task_id=managed['context']['task_id'],
                                                  action_id=action_id))['action']
    context = managed['context']
    proposal = dict(schema_version='1.0', task_id=context['task_id'],
        resource_id=context['resource_id'], capability='terminal.run', args=plan['args'],
        reason=plan['reason'], idempotency_key=context['operation_key'])
    expected = hashlib.sha256(canonical(proposal).encode()).hexdigest()
    if (action['id'] != action_id or action['task_id'] != context['task_id']
            or action['proposal_digest'] != expected):
        raise ValueError('Core action does not match trusted original plan')
    states = {'intent': 'queued', 'executing': 'running', 'failed': 'failed',
              'unknown': 'unknown_effect'}
    if action['state'] == 'done':
        task['status'] = 'completed' if action['verified'] else 'verifying'
    elif action['state'] in states:
        task['status'] = states[action['state']]
    else:
        raise ValueError('Unknown authoritative action outcome')
    return task


def dispatch_prompt(prompt_id, plan):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise PermissionError('Trusted Linux root operator required')
    identifier(prompt_id)
    binding = dict(prompt_id=prompt_id, human_uid=human_uid())
    status = control_request('prompt_status', binding)['prompt']
    if status['id'] != prompt_id:
        raise ValueError('Prompt status identity changed')
    if status['state'] == 'received':
        managed = create_from_prompt(prompt_id)
    elif status['state'] == 'task_created':
        managed = control_request('prompt_context', binding)['managed']
    else:
        raise ValueError('Prompt creation is uncertain; no automatic reallocation')
    if managed['prompt_id'] != prompt_id:
        raise ValueError('Stored context belongs to another prompt')
    return run_mock_step(managed, plan)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description='Trusted operator: bounded core lifecycle cycle')
    parser.add_argument('--mock', action='store_true')
    args = parser.parse_args(argv)
    if not args.mock:
        parser.error('This deterministic adapter requires explicit --mock')
    try:
        if os.geteuid() != 0 or sys.platform != 'linux':
            raise PermissionError('Trusted Linux root operator required')
        packet = sys.stdin.buffer.read(65537)
        if not 1 <= len(packet) <= 65536:
            raise ValueError('Invalid lifecycle packet size')
        value = json.loads(packet.decode('utf8'), object_pairs_hook=unique_object)
        if not isinstance(value, dict) or set(value) not in (
                {'managed', 'plan'}, {'prompt_id', 'plan'}):
            raise ValueError('Unknown lifecycle fields')
        task = (dispatch_prompt(value['prompt_id'], value['plan']) if 'prompt_id' in value
                else run_mock_step(value['managed'], value['plan']))
        print(canonical(dict(schema_version='1.0', ok=True, task=task)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print(canonical(dict(schema_version='1.0', ok=False, error='uncertain')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
