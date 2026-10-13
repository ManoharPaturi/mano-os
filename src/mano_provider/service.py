"""One broker-only protected provider health request; dispatch remains disabled."""

import json
import pwd
import socket

from mano_protocol.actions import canonical, unique_object
from mano_protocol.transport import receive

from .credentials import load
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
    config, _key = load()
    return dict(schema_version='1.0', ok=True, provider=config['provider'], model=config['model'],
                credentials_present=True, execution_enabled=False)


def main():
    connection = None
    result = dict(schema_version='1.0', ok=False, error='denied')
    try:
        verify_current()  # Before socket requests or credentials are read.
        connection = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_SEQPACKET)
        connection.settimeout(15)
        peer, packet = receive(connection)
        result = health(packet, peer)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RecursionError):
        result = dict(schema_version='1.0', ok=False, error='denied')
    finally:
        if connection is not None:
            try:
                connection.send(canonical(result).encode())
            except OSError:
                pass
            connection.close()
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
