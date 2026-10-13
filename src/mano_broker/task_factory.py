"""Root-only administrative task creation; no model-selected UID, path or command."""

import argparse
import array
import json
import os
import pwd
import secrets
import socket
import stat
import sys
from pathlib import Path

from mano_protocol.actions import MAX_PACKET, canonical, identifier, text, unique_object
from mano_protocol.transport import CREDENTIALS, Peer, reply

from .identities import allocate_identity
from .workspaces import create_workspace

SOCKET = '/run/mano-broker/provision.sock'
HUMAN_POLICY = Path('/etc/mano/human.uid')


def human_uid():
    for directory in HUMAN_POLICY.parents:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted human policy parent')
    fd = os.open(HUMAN_POLICY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 30):
            raise ValueError('Invalid protected human policy')
        value = os.read(fd, 31).decode('ascii').removesuffix('\n')
    finally:
        os.close(fd)
    if not value.isascii() or not value.isdecimal() or str(int(value)) != value:
        raise ValueError('Invalid canonical human UID')
    uid = int(value)
    account = pwd.getpwuid(uid)
    if (uid < 1000 or (account.pw_name.startswith('mano-') and account.pw_name != 'mano-human')
            or account.pw_shell in {'/usr/sbin/nologin', '/bin/false'}):
        raise ValueError('Human policy must name a login identity')
    return uid


def create_task(prompt):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise PermissionError('Task creation requires trusted root operator')
    text(prompt, 8192)
    human = human_uid()
    identity = allocate_identity()
    workspace, fd = create_workspace(human_uid=human, caller_uid=identity.uid)
    try:
        broker = pwd.getpwnam('mano-broker')
        envelope = dict(schema_version='1.0', operation='provision_task', body=dict(
            human_uid=human, caller_uid=identity.uid, mode='supervised', classification='internal'))
        packet = canonical(envelope).encode()
        if len(packet) > MAX_PACKET:
            raise ValueError('Invalid task provisioning packet')
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(3)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.connect(SOCKET)
            creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
            if creator.uid != 0 or creator.gid != 0:
                raise ValueError('Provisioning listener must be root activated')
            sent = connection.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                 array.array('i', [fd]))])
            if sent != len(packet):
                raise ValueError('Incomplete task provisioning; do not retry')
            _, result = reply(connection, expected_uid=broker.pw_uid, expected_gid=broker.pw_gid)
        if result.get('ok') is not True:
            raise ValueError('Broker denied new task provisioning')
        return dict(context=dict(task_id=identifier(result['task_id']),
            resource_id=identifier(result['resource_id']), operation_key=secrets.token_hex(16),
            prompt=prompt), workspace=str(workspace), caller_uid=identity.uid,
            caller_name=identity.name, mode='supervised')
    finally:
        os.close(fd)
    # On uncertain provisioning, preserve the locked identity/workspace. Never recycle UID
    # or recursively delete data that another trusted observer may already have received.


def control_request(operation, body):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise PermissionError('Trusted Linux root operator required')
    broker = pwd.getpwnam('mano-broker')
    packet = canonical(dict(schema_version='1.0', operation=operation, body=body)).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(3)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        connection.connect('/run/mano-broker/control.sock')
        creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
        if creator.uid != 0 or creator.gid != 0:
            raise ValueError('Control listener must be root activated')
        if connection.send(packet) != len(packet):
            raise ValueError('Incomplete control request; no implicit retry')
        _, result = reply(connection, expected_uid=broker.pw_uid, expected_gid=broker.pw_gid)
    if result.get('ok') is not True:
        raise ValueError('Protected prompt transition denied')
    return result


def create_from_prompt(prompt_id):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise PermissionError('Trusted Linux root operator required')
    identifier(prompt_id)
    human = human_uid()
    binding = dict(prompt_id=prompt_id, human_uid=human)
    try:
        claimed = control_request('claim_prompt', binding)['prompt']
        if claimed['id'] != prompt_id:
            raise ValueError('Prompt claim identity changed')
        result = create_task(claimed['prompt'])
        result['context']['operation_key'] = prompt_id
        attached = control_request('attach_prompt_task', binding | {
            'task_id': result['context']['task_id']})['prompt']
        if (attached['id'] != prompt_id or attached['state'] != 'task_created'
                or attached['task_id'] != result['context']['task_id']):
            raise ValueError('Uncertain prompt/task attachment')
        result['prompt_id'] = prompt_id
        return result
    except BaseException:
        try:
            control_request('uncertain_prompt_creation', binding)
        except (OSError, ValueError, KeyError, TypeError):
            pass  # Recovery also makes an outstanding claim uncertain on broker restart.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='Trusted operator: provision a managed task')
    parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or sys.platform != 'linux':
            raise PermissionError('Trusted Linux root operator required')
        packet = sys.stdin.buffer.read(MAX_PACKET + 1)
        if not 1 <= len(packet) <= MAX_PACKET:
            raise ValueError('Invalid bounded task input')
        value = json.loads(packet.decode('utf8'), object_pairs_hook=unique_object)
        if not isinstance(value, dict) or set(value) not in ({'prompt'}, {'prompt_id'}):
            raise ValueError('Task input accepts only human prompt text')
        result = (create_from_prompt(value['prompt_id']) if 'prompt_id' in value
                  else create_task(value['prompt']))
        print(canonical(dict(schema_version='1.0', ok=True, task=result)))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(canonical(dict(schema_version='1.0', ok=False, error='denied')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
