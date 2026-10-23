"""Private Broker-authenticated Root package transaction; no shell/argv API."""

import hashlib
import json
import os
import pwd
import re
import select
import selectors
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from mano_broker.package_catalog import trusted
from mano_protocol.actions import ActionRequest, canonical, identifier, unique_object
from mano_protocol.packages import result_digest
from mano_protocol.stop_state import snapshot
from mano_protocol.transport import receive
from mano_runtime import package_archives, package_attempts, package_catalog, recovery
from mano_runtime.package_resolution import current_plan, expected

SOCKET = '/run/mano-package-apply/request.sock'
DOMAIN = '/mano.slice/mano-package.slice/'
ENV = {'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'PYTHONPATH': '/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE': '1'}
MAX_LOG = 1024 * 1024
STAGE = 'activation'


def domain():
    recovery.root_guard()
    group = Path('/proc/self/cgroup').read_text().strip()
    if not group.startswith('0::' + DOMAIN) or '\n' in group:
        raise PermissionError('Package transaction must already be in the protected Stop domain')


def decode(body):
    if not isinstance(body, dict) or set(body) != {
            'action_id', 'request', 'plan', 'boot_id', 'native_generation', 'expires'}:
        raise ValueError('Exact package transaction required')
    identifier(body['action_id'])
    request = ActionRequest.parse(canonical(body['request']).encode())
    if request.capability != 'packages.apply_install':
        raise ValueError('Separate package apply capability required')
    args = json.loads(request.args_json)
    plan = body['plan']
    expected(plan)
    if result_digest(plan, expected=expected(plan)) != args['plan_sha256']:
        raise ValueError('Approved full package plan changed')
    if (type(body['native_generation']) is not int or body['native_generation'] < 0
            or type(body['expires']) not in {int, float}
            or not time.monotonic() < body['expires'] <= time.monotonic() + 60
            or body['boot_id'] != package_attempts.boot()):
        raise PermissionError('Current bounded package authority required')
    return request, plan


def observe(body, broker_fd=None):
    connection = None
    if isinstance(broker_fd, tuple):
        broker_fd, connection = broker_fd
    if connection is not None and select.select([connection], [], [], 0)[0]:
        raise PermissionError('Broker disconnected or sent an unexpected continuation')
    state = snapshot()
    if (state.latched or state.generation != body['native_generation']
            or time.monotonic() >= body['expires']
            or (broker_fd is not None and select.select([broker_fd], [], [], 0)[0])):
        raise PermissionError('Package authority stopped, disconnected or expired')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Package redirects require fresh bounded source validation')


def archive_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('Bounded Debian archive location required')
    uri = urllib.parse.urlsplit(value)
    if (uri.scheme not in {'http', 'https'} or uri.hostname not in {
            'deb.debian.org', 'security.debian.org'} or uri.username or uri.password
            or uri.port is not None or uri.query or uri.fragment
            or not re.fullmatch(r'/(debian|debian-security)/pool/[A-Za-z0-9_./+%:~-]+', uri.path)
            or '..' in urllib.parse.unquote(uri.path)):
        raise ValueError('Only fixed official Debian archive sources are allowed')
    return urllib.parse.urlunsplit(('https', uri.hostname, uri.path, '', ''))


def acquire(plan, body, broker_fd):
    """Bounded explicit acquisition under package locks; sealed custody follows."""
    with current_plan(plan):
        package_attempts.ensure_available_locked(body['action_id'])
        observe(body, broker_fd)
        packet = subprocess.run(
            ['/usr/bin/python3', '-P', '-m', 'mano_runtime.package_apt', '--locations'],
            input=canonical(plan).encode(), capture_output=True, timeout=30, env=ENV, cwd='/')
        if packet.returncode or packet.stderr or len(packet.stdout) > 32768:
            # Metadata workers have no script output; emit only fixed stage/type.
            for line in packet.stderr.splitlines():
                if line.startswith(b'MANO_PACKAGE_ERROR='):
                    detail = json.loads(line.split(b'=', 1)[1], object_pairs_hook=unique_object)
                    if (detail.get('stage') in {'admission', 'cache', 'archives'}
                            and detail.get('error_type') in {'PermissionError', 'ValueError',
                                'Error', 'SystemError', 'TypeError', 'AttributeError', 'OSError',
                                'KeyError', 'RuntimeError', 'TimeoutError', 'Unknown'}):
                        print(canonical(dict(event='package-metadata-worker-denied',
                            stage=detail['stage'], error_type=detail['error_type'])),
                            file=sys.stderr, flush=True)
            raise ValueError('Root archive-source resolution unavailable')
        sources = json.loads(packet.stdout, object_pairs_hook=unique_object)
        rows = {row['archive_sha256']: row for row in plan['changes']
                if row['operation'] != 'remove'}
        if set(sources) != set(rows):
            raise ValueError('Archive sources differ from the approved solution')
        if (any(row['download_bytes'] > package_archives.MAX_ARCHIVE for row in rows.values())
                or sum(row['download_bytes'] for row in rows.values())
                > package_archives.MAX_TOTAL):
            raise ValueError('Package archive acquisition exceeds byte budget')
        trusted(package_archives.CACHE, directory=True)
        entries = list(package_archives.CACHE.iterdir())
        if len(entries) + len(rows) * 2 > package_archives.MAX_ENTRIES:
            raise ValueError('Archive cache retention requires operator review')
        present, scanned = set(), 0
        from mano_broker.package_catalog import read

        sizes = {row['download_bytes'] for row in rows.values()}
        for path in entries:
            if not path.name.endswith('.deb'):
                continue
            info = trusted(path)
            if info.st_size not in sizes:
                continue
            scanned += info.st_size
            if scanned > package_archives.MAX_SCAN:
                raise ValueError('Archive acquisition inventory exceeds scan budget')
            present.add(hashlib.sha256(read(path, package_archives.MAX_ARCHIVE)).hexdigest())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        downloaded = []
        for sha, row in rows.items():
            observe(body, broker_fd)
            destination = package_archives.CACHE / (sha + '.deb')
            if sha in present or destination.exists() or destination.is_symlink():
                # The sealed-custody stage rechecks trusted inode/type, bytes and metadata.
                continue
            url = archive_url(sources[sha])
            stage = package_archives.CACHE / ('.mano-' + body['action_id'] + '-' + sha)
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            # Partial files remain evidence, and are never accepted as .deb archives.
            digest, count = hashlib.sha256(), 0
            with os.fdopen(fd, 'wb') as target, opener.open(url, timeout=5) as response:
                if response.status != 200:
                    raise ValueError('Unexpected Debian archive response')
                while data := response.read(min(65536, row['download_bytes'] + 1 - count)):
                    observe(body, broker_fd)
                    count += len(data)
                    if count > row['download_bytes']:
                        raise ValueError('Archive exceeded the exact approved length')
                    digest.update(data)
                    target.write(data)
                if count != row['download_bytes'] or digest.hexdigest() != sha:
                    raise ValueError('Downloaded archive differs from signed package metadata')
                target.flush()
                os.fsync(target.fileno())
            os.link(stage, destination, follow_symlinks=False)  # Never replace an existing object.
            stage.unlink()  # Only this attempt's fresh staging name, after verified publication.
            package_attempts.sync(destination.parent)
            downloaded.append(sha)
        observe(body, broker_fd)
        return dict(network_used=bool(downloaded), downloaded_sha256=sorted(downloaded),
                    download_bytes=sum(rows[sha]['download_bytes'] for sha in downloaded))


def sandbox(archives, body):
    """Fixed namespace construction; no model path, environment or command input."""
    argv = ['/usr/bin/bwrap', '--die-with-parent', '--new-session',
            '--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts',
            '--unshare-cgroup', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
            '--ro-bind', '/sys', '/sys', '--tmpfs', '/run', '--tmpfs', '/tmp',
            '--clearenv', '--cap-drop', 'ALL']
    for capability in ('CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER', 'CAP_FSETID',
                       'CAP_SETUID', 'CAP_SETGID'):
        argv += ['--cap-add', capability]
    # Mount writable ancestors themselves so a child cannot rename an ancestor
    # and shadow a protected descendant through the shared backing filesystem.
    for path in ('/usr', '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/libexec', '/usr/share',
                 '/usr/lib/systemd', '/usr/lib/systemd/system', '/etc', '/etc/systemd',
                 '/etc/systemd/system', '/var', '/var/lib', '/var/cache', '/var/log', '/var/spool'):
        if Path(path).exists():
            argv += ['--bind', path, path]
    # Protect authority, credentials, recovery history and human data from scripts.
    for path in ('/home', '/root', '/mnt', '/media', '/srv', '/opt', '/.snapshots',
                 '/etc/mano', '/etc/ssh', '/etc/ssl/private', '/var/lib/mano-broker',
                 '/var/lib/mano-workspaces',
                 '/var/lib/private', '/var/lib/mano-provider'):
        if Path(path).exists():
            argv += ['--tmpfs', path]
    for path in ('/usr/lib/mano-os', '/usr/lib/mano-broker', '/var/lib/mano-packages',
                 '/var/lib/mano-stopd',
                 '/boot', '/etc/pam.d', '/etc/snapper',
                 '/etc/passwd', '/etc/group', '/etc/sudoers', '/etc/sudoers.d'):
        if Path(path).exists():
            argv += ['--ro-bind', path, path]
    for path in ('/etc/shadow', '/etc/gshadow', '/etc/ld.so.preload'):
        if Path(path).exists():
            argv += ['--ro-bind', '/dev/null', path]
    for directory in ('/usr/bin', '/usr/libexec', '/usr/lib/systemd/system', '/etc/systemd/system'):
        for path in Path(directory).glob('mano-*'):
            argv += ['--ro-bind', str(path), str(path)]
    argv += ['--tmpfs', '/etc/dpkg', '--dir', '/etc/dpkg/dpkg.cfg.d',
             '--dir', '/run/mano-package-archives']
    for archive in archives:
        os.lseek(archive['fd'], 0, os.SEEK_SET)
        filename = (archive['name'] + '_' + archive['version'].replace(':', '%3a') +
                    '_' + archive['architecture'] + '.deb')
        argv += ['--ro-bind-data', str(archive['fd']), '/run/mano-package-archives/' + filename]
    for key, value in (ENV | {'DPKG_FRONTEND_LOCKED': '1', 'MANO_PACKAGE_NAMESPACE': '1',
                             'DEBIAN_FRONTEND': 'noninteractive',
                             'MANO_PACKAGE_GENERATION': str(body['native_generation']),
                             'MANO_PACKAGE_EXPIRES': repr(body['expires'])}).items():
        argv += ['--setenv', key, value]
    return argv + ['--chdir', '/', '/usr/libexec/mano-package-guard']


def run_child(plan, archives, body, broker_fd):
    child = subprocess.Popen(sandbox(archives, body), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, cwd='/',
        pass_fds=tuple(row['fd'] for row in archives), start_new_session=True)
    output = bytearray()
    try:
        child.stdin.write(canonical(plan).encode())
        child.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                observe(body, broker_fd)
                for key, _ in selector.select(.05):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(data)
                        if len(output) > MAX_LOG:
                            raise ValueError('Package child exceeded bounded output')
        if child.wait(timeout=1) != 0:
            # Only fixed stage/type diagnostics reach the Root journal, never
            # raw maintainer output, URLs, request data, paths or credentials.
            for line in output.splitlines():
                if line.startswith(b'MANO_PACKAGE_ERROR='):
                    detail = json.loads(line.split(b'=', 1)[1], object_pairs_hook=unique_object)
                    if (detail.get('stage') in {'admission', 'boundary', 'cache', 'archives',
                                               'commit', 'native-guard'}
                            and detail.get('error_type') in {'PermissionError', 'ValueError',
                                'Error', 'SystemError', 'TypeError', 'AttributeError', 'OSError',
                                'KeyError', 'RuntimeError', 'TimeoutError',
                                'NativeGuard', 'Unknown'}):
                        print(canonical(dict(event='package-worker-denied',
                            stage=detail['stage'], error_type=detail['error_type'])),
                            file=sys.stderr, flush=True)
            raise ValueError('Package worker failed; inspect recovery custody')
        witnesses = [line.split(b'=', 1)[1] for line in output.splitlines()
                     if line.startswith(b'MANO_PACKAGE_BOUNDARY=')]
        if len(witnesses) != 1:
            raise ValueError('One native package boundary witness required')
        witness = json.loads(witnesses[0], object_pairs_hook=unique_object)
        fields = {'network_socket_denied', 'protected_code_readonly', 'cgroup_control_readonly',
                  'host_shadow_hidden', 'approval_ipc_hidden', 'protected_ancestors_mounted',
                  'no_new_privileges', 'seccomp_active', 'native_stop_authority_readonly'}
        if (set(witness) != fields | {'namespaces'}
                or any(witness[key] is not True for key in fields)
                or set(witness['namespaces']) != {'mnt', 'net', 'ipc', 'pid', 'cgroup'}
                or any(value == os.readlink('/proc/self/ns/' + kind)
                       for kind, value in witness['namespaces'].items())):
            raise ValueError('Package boundary witness is incomplete or not private')
        return hashlib.sha256(output).hexdigest(), witness
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if not child.stdin.closed:
            child.stdin.close()
        child.stdout.close()
        child.stderr.close()


def drained(body, broker_fd):
    group = Path('/proc/self/cgroup').read_text().strip()
    if not group.startswith('0::' + DOMAIN) or '\n' in group:
        raise PermissionError('Package Stop domain changed')
    path = Path('/sys/fs/cgroup') / group[3:].lstrip('/') / 'cgroup.procs'
    limit = time.monotonic() + 1
    while True:
        observe(body, broker_fd)
        members = path.read_text().split()
        if members == [str(os.getpid())]:
            return
        if time.monotonic() >= limit:
            raise ValueError('Package descendants remain; completion is uncertain')
        time.sleep(.02)


def execute(body, *, broker_fd=None):
    global STAGE
    STAGE = 'domain'
    domain()
    STAGE = 'decode'
    request, plan = decode(body)
    observe(body, broker_fd)
    STAGE = 'layout'
    layout = recovery.layout()
    STAGE = 'space-reserve'
    reserve = 2 * 1024**3 + max(plan['net_installed_bytes'], 0) + plan['download_bytes']
    if layout['free_bytes'] < reserve:
        print(canonical(dict(event='package-space-reserve-denied',
                             available_bytes=layout['free_bytes'], required_bytes=reserve)),
              file=sys.stderr, flush=True)
        raise ValueError('Insufficient free space for package reserve; peak remains unmeasured')
    STAGE = 'acquisition'
    acquisition = acquire(plan, body, broker_fd)
    STAGE = 'sealed-custody'
    with package_archives.verified_archives(plan) as staged:
        scope = recovery.require_locked()
        observe(body, broker_fd)
        package_attempts.ensure_available_locked(body['action_id'])
        STAGE = 'checkpoint'
        checkpoint = recovery.create_locked()
        package_attempts.begin_locked(body['action_id'], request.digest, checkpoint['recovery_id'])
        STAGE = 'child'
        observe(body, broker_fd)
        with scope.dpkg_backend():
            log_sha, boundary = run_child(plan, staged['archives'], body, broker_fd)
        drained(body, broker_fd)
        STAGE = 'postconditions'
        outcome = package_attempts.complete_locked(body['action_id'], request.digest, plan)
        STAGE = 'catalog-refresh'
        catalog = package_catalog.build()
        drained(body, broker_fd)
        return dict(schema_version='1.0', ok=True, action_id=body['action_id'],
                    request_sha256=request.digest, outcome=outcome,
                    checkpoint=checkpoint['recovery_id'], catalog_id=catalog['catalog_id'],
                    log_sha256=log_sha, boundary=boundary, acquisition=acquisition,
                    package_children_drained=True,
                    peak_space_bytes=None)


def main():
    domain()
    if sys.argv[1:]:
        raise ValueError('Socket activation only')
    with socket.socket(fileno=0) as connection:
        connection.settimeout(2)
        if connection.getsockname() != SOCKET:
            raise PermissionError('Fixed private package socket required')
        broker = pwd.getpwnam('mano-broker')
        peer, packet = receive(connection)
        if peer.uid != broker.pw_uid or peer.gid != broker.pw_gid or peer.uid == 0:
            raise PermissionError('Only the trusted Broker can request a package transaction')
        body = json.loads(packet, object_pairs_hook=unique_object)
        fd = os.pidfd_open(peer.pid)
        try:
            value = execute(body, broker_fd=(fd, connection))
        except Exception as error:
            print(canonical(dict(event='package-transaction-denied', stage=STAGE,
                                 error_type=type(error).__name__)), file=sys.stderr, flush=True)
            # No retry, raw package output or misleading success after uncertainty.
            value = dict(schema_version='1.0', ok=False, error='package-outcome-unknown')
        finally:
            os.close(fd)
        connection.sendall(canonical(value).encode())


if __name__ == '__main__':
    main()
