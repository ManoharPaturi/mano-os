"""One opaque TLS stream to a fixed provider; no API key or endpoint input."""

import os
import pwd
import socket
import stat
import sys
import time
from pathlib import Path

from mano_protocol.credential_files import private_file
from mano_protocol.provider import decode
from mano_protocol.provider_endpoint import addresses
from mano_protocol.stop_state import snapshot
from mano_protocol.transport import CREDENTIALS, Peer

from .profile import verify_current
from .relay import relay


def enabled():
    base = Path(os.environ.get('CREDENTIALS_DIRECTORY', ''))
    if (not base.is_absolute() or base.parent != Path('/run/credentials')
            or not base.name.startswith('mano-egress@') or not base.name.endswith('.service')):
        raise ValueError('Fixed egress credential required')
    for parent in base.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted egress credential ancestor')
    value = decode(private_file(base, 'config', 1024), 1024)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'enabled'}
            or value['schema_version'] != '1.0' or type(value['enabled']) is not bool):
        raise ValueError('Invalid Root egress policy')
    return value['enabled']


def serve(connection):
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
        raise ValueError('Private provider stream required')
    provider = pwd.getpwnam('mano-provider')
    peer = Peer(*CREDENTIALS.unpack(connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
    if (provider.pw_uid <= 0 or provider.pw_gid <= 0 or peer.pid <= 0
            or (peer.uid, peer.gid) != (provider.pw_uid, provider.pw_gid)):
        raise ValueError('Original provider identity required')
    if not enabled():
        raise ValueError('Root egress policy disabled')
    deadline = time.monotonic() + 30
    before = snapshot()
    if before.latched:
        raise ValueError('Native Stop prevents provider egress')
    family, kind, protocol, _name, address = addresses()[0]
    after = snapshot()
    if after.latched or after.generation != before.generation:
        raise ValueError('Native Stop changed during provider resolution')
    with socket.socket(family, kind, protocol) as upstream:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Provider resolution exceeded deadline')
        upstream.settimeout(remaining)
        upstream.connect(address)  # Validated numeric endpoint; no second resolution or retry.
        return relay(connection, upstream, deadline=deadline)


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError('No egress arguments accepted')
        verify_current()
        with socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            serve(connection)
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        code = 'policy-disabled' if str(error) == 'Root egress policy disabled' else 'denied'
        # Never log opaque bytes or exception text.
        print('egress-request-denied code=' + code, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
