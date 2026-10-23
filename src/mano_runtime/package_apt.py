"""Fixed Root APT workers: signed archive locations or an isolated package commit.

No public listener. The parent owns native approval, snapshots, locks and Stop.
The apply worker must run inside the restricted private package namespace.
"""

import contextlib
import errno
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

from mano_broker.package_catalog import load
from mano_broker.package_solver import canonical, forecast, prepare_apt_root
from mano_protocol.actions import unique_object
from mano_protocol.stop_state import STATE_FILE, snapshot
from mano_runtime.package_attempts import guard
from mano_runtime.package_resolution import expected

ARCHIVES = Path('/run/mano-package-archives')
STAGE = 'admission'


@contextlib.contextmanager
def cache_for(plan, *, actual=False):
    args = expected(plan)
    catalog, manifest = load(args['catalog_id'])
    import apt_pkg

    with tempfile.TemporaryDirectory(prefix='mano-apt-') as temporary:
        root = Path(temporary)
        prepare_apt_root(root, catalog=catalog)
        apt_pkg.config.clear()
        apt_pkg.config.set('Dir', str(root))
        apt_pkg.config.set('Dir::Etc', str(root / 'etc/apt'))
        apt_pkg.init_config()
        import apt
        import apt.progress.base

        for key, value in {
            'APT::Architecture': 'amd64', 'APT::Architectures::': 'amd64',
            'APT::Install-Recommends': 'false', 'APT::Install-Suggests': 'false',
            'Dir::Bin::dpkg': '/usr/bin/dpkg', 'DPkg::Use-Pty': 'false',
            'DPkg::Options::': '--force-confold',
        }.items():
            apt_pkg.config.set(key, value)
        if actual:
            apt_pkg.config.set('Dir::State::status', '/var/lib/dpkg/status')
            apt_pkg.config.set('Dir::State::extended_states', '/var/lib/apt/extended_states')
        cache = apt.Cache(progress=apt.progress.base.OpProgress(), memonly=True)
        try:
            if cache.broken_count or cache.dpkg_journal_dirty:
                raise ValueError('Unsettled package state')
            value = forecast(cache, args['names'], args['catalog_id'], manifest)
            if canonical(value) != canonical(plan):
                raise ValueError('Package worker solution changed')
            yield cache, apt_pkg
        finally:
            cache.close()


def locations(plan):
    with cache_for(plan) as (cache, _):
        return {row['archive_sha256']: cache[row['name']].candidate.uri
                for row in plan['changes'] if row['operation'] != 'remove'}


def boundary():
    """Fail before effects if the fixed native/namespace boundary is missing."""
    guard()
    if os.getpid() != 2:
        raise PermissionError('Private package PID namespace required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if status['NoNewPrivs'].strip() != '1' or status['Seccomp'].strip() != '2':
        raise PermissionError('Native package restrictions absent')
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        connection.close()
        raise PermissionError('Package network socket was not denied')
    for path in ('/usr/lib/mano-os/mano_runtime/package_apt.py',
                 '/sys/fs/cgroup/cgroup.procs', str(STATE_FILE)):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            os.close(fd)
            raise PermissionError('Protected package path opened for writing')
    if Path('/etc/shadow').read_bytes() or Path('/run/mano-approval/human.sock').exists():
        raise PermissionError('Host credentials or approval IPC visible to package worker')
    mounts = {line.split()[4]: line.split()[5].split(',')
              for line in Path('/proc/self/mountinfo').read_text().splitlines()}
    if 'ro' not in mounts.get('/', []) or any(path not in mounts for path in
            ('/usr', '/usr/lib', '/usr/bin', '/etc', '/var', '/var/lib')):
        raise PermissionError('Protected mount ancestry absent')
    return dict(network_socket_denied=True, protected_code_readonly=True,
                cgroup_control_readonly=True, host_shadow_hidden=True, approval_ipc_hidden=True,
                protected_ancestors_mounted=True, no_new_privileges=True, seccomp_active=True,
                native_stop_authority_readonly=True,
                namespaces={kind: os.readlink('/proc/self/ns/' + kind)
                            for kind in ('mnt', 'net', 'ipc', 'pid', 'cgroup')})


def authority():
    guard()
    try:
        generation = int(os.environ['MANO_PACKAGE_GENERATION'])
        deadline = float(os.environ['MANO_PACKAGE_EXPIRES'])
    except (KeyError, ValueError):
        raise PermissionError('Fixed package authority tags required') from None
    state = snapshot()
    now = time.monotonic()
    if state.latched or state.generation != generation or not now < deadline <= now + 60:
        raise PermissionError('Package authority expired or native Stop changed')


def commit(plan):
    global STAGE
    if (os.environ.get('DPKG_FRONTEND_LOCKED') != '1'
            or os.environ.get('MANO_PACKAGE_NAMESPACE') != '1'
            or not ARCHIVES.is_dir()):
        raise PermissionError('Private package namespace and frontend protocol required')
    STAGE = 'cache'
    with cache_for(plan, actual=True) as (cache, apt_pkg):
        STAGE = 'archives'
        apt_pkg.config.set('Dir::Cache::archives', str(ARCHIVES) + '/')
        manager = apt_pkg.PackageManager(cache._depcache)
        fetcher = apt_pkg.Acquire()
        sources = apt_pkg.SourceList()
        sources.read_main_list()
        records = apt_pkg.PackageRecords(cache._cache)
        if not manager.get_archives(fetcher, sources, records) or fetcher.fetch_needed:
            raise ValueError('Every package archive must already be sealed and present')
        if fetcher.run() != apt_pkg.Acquire.RESULT_CONTINUE or any(
                not item.complete for item in fetcher.items):
            raise ValueError('Sealed package archives unavailable')
        STAGE = 'commit'
        authority()
        status = os.open('/dev/null', os.O_WRONLY | os.O_CLOEXEC)
        try:
            code = manager.do_install(status)
        finally:
            os.close(status)
        if code != apt_pkg.PackageManager.RESULT_COMPLETED:
            raise ValueError('Package commit did not complete')
        # APT's dpkg package manager writes the depcache auto-bits as part
        # of Go(). Python's DepCache does not expose a write_state_file API.


def main():
    global STAGE
    guard()
    if sys.argv[1:] not in (['--locations'], ['--commit']):
        raise ValueError('Fixed package worker mode required')
    data = sys.stdin.buffer.read(65537)
    if len(data) > 65536:
        raise ValueError('Package plan exceeds worker budget')
    plan = json.loads(data, object_pairs_hook=unique_object)
    expected(plan)
    if sys.argv[1:] == ['--locations']:
        packet = canonical(locations(plan)).encode()
        if len(packet) > 32768:
            raise ValueError('Archive locations exceed budget')
        sys.stdout.buffer.write(packet)
    else:
        STAGE = 'boundary'
        print('MANO_PACKAGE_BOUNDARY=' + canonical(boundary()), flush=True)
        commit(plan)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        known = {'PermissionError', 'ValueError', 'Error', 'SystemError', 'TypeError',
                 'AttributeError', 'OSError', 'KeyError', 'RuntimeError', 'TimeoutError'}
        kind = type(error).__name__
        print('MANO_PACKAGE_ERROR=' + canonical(dict(stage=STAGE,
            error_type=kind if kind in known else 'Unknown')), file=sys.stderr, flush=True)
        sys.exit(2)
