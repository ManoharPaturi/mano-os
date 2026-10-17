"""One protected request; generation is policy-gated and network remains isolated."""

import json
import pwd
import socket
import sys
import time
from pathlib import Path

from mano_protocol.actions import canonical, unique_object
from mano_protocol.transport import receive

from .credentials import load, load_key, load_policy
from .job_request import authorize, execute
from .profile import verify_current


def health(packet, peer):
    broker = pwd.getpwnam('mano-broker')
    if broker.pw_uid == 0 or (peer.uid, peer.gid) != (broker.pw_uid, broker.pw_gid):
        raise ValueError('Trusted broker peer required')
    value = json.loads(packet.decode('utf8'), object_pairs_hook=unique_object)
    if (not isinstance(value, dict)
            or set(value) != {'schema_version', 'operation', 'body'}
            or value['schema_version'] != '1.0' or value['operation'] != 'health'
            or value['body'] != {}):
        raise ValueError('Provider dispatch is not enabled')
    try:
        config, _key = load()
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        codes = {'Unknown provider credential', 'Unsafe credential directory',
                 'credential-file-type', 'credential-file-owner', 'credential-file-mode',
                 'credential-file-links', 'credential-file-size', 'Provider credential changed',
                 'Fixed service credential directory required', 'Untrusted credential ancestor',
                 'Invalid fixed provider policy', 'Invalid explicit model identifier',
                 'Invalid provider credential'}
        if str(error) in codes:
            raise ValueError(str(error)) from None
        raise ValueError('provider-credential-load-denied') from None
    return dict(schema_version='1.0', ok=True, provider=config['provider'], model=config['model'],
                credentials_present=True, execution_enabled=False)


def current_boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def generation(connection, packet, peer):
    broker = pwd.getpwnam('mano-broker')
    if broker.pw_uid == 0 or (peer.uid, peer.gid) != (broker.pw_uid, broker.pw_gid):
        raise ValueError('Trusted broker peer required')
    config = load_policy()
    boot_id = current_boot()
    # Refuse disabled/invalid/stale jobs before opening the key. execute repeats
    # authorization after key loading, using fresh clocks just before the call.
    authorize(packet, peer, config=config, boot_id=boot_id,
              now=time.monotonic(), wall_time=int(time.time()))
    key = load_key()
    execute(connection, packet, peer, config=config, credential=key, boot_id=boot_id)


def main():
    connection = None
    result = dict(schema_version='1.0', ok=False, error='denied')
    stage = 'profile'
    sealed_sent = False
    try:
        verify_current()  # Before socket requests or credentials are read.
        stage = 'socket'
        connection = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_SEQPACKET)
        connection.settimeout(15)
        stage = 'receive'
        peer, packet = receive(connection)
        value = json.loads(packet.decode('utf8'), object_pairs_hook=unique_object)
        if isinstance(value, dict) and value.get('operation') == 'generate':
            stage = 'generation'
            generation(connection, packet, peer)
            sealed_sent = True
            result = dict(schema_version='1.0', ok=True)
        else:
            stage = 'health'
            result = health(packet, peer)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RecursionError) as error:
        # Emit fixed codes only: exception text may contain provider secrets.
        known = {
            'Protected provider requires its Linux service': 'identity-platform',
            'Protected provider identity absent': 'identity-account',
            'Protected provider process restrictions absent': 'process-profile',
            'Protected provider is outside the Stop domain': 'stop-domain',
            'Provider cgroup is not root managed': 'cgroup-owner',
            'Provider resource constraints absent': 'cgroup-limits',
            'provider-credential-load-denied': 'credentials',
        }
        credential_codes = {
            'Unknown provider credential': 'credential-name',
            'Unsafe credential directory': 'credential-directory',
            'Provider credential changed': 'credential-changed',
            'Fixed service credential directory required': 'credential-path',
            'Untrusted credential ancestor': 'credential-ancestor',
            'Invalid fixed provider policy': 'credential-policy',
            'Invalid explicit model identifier': 'credential-model',
            'Invalid provider credential': 'credential-key-format',
        }
        known.update(credential_codes)
        for item in ('type', 'owner', 'mode', 'links', 'size'):
            known[f'credential-file-{item}'] = f'credential-file-{item}'
        code = known.get(str(error), 'denied')
        print(f'provider-request-denied stage={stage} code={code}', file=sys.stderr)
        result = dict(schema_version='1.0', ok=False, error='denied')
    finally:
        if connection is not None:
            if not sealed_sent:
                try:
                    connection.send(canonical(result).encode())
                except OSError:
                    pass
            connection.close()
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
