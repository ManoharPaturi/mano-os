"""Fixed Root APT workers: signed archive locations or an isolated package commit.

No public listener. The parent owns native approval, snapshots, locks and Stop.
The apply worker must run inside the restricted private package namespace.
"""

import contextlib
import ctypes
import errno
import json
import os
import socket
import stat
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
BOUNDARY_CHECK = 'entry'
BOUNDARY_KERNEL = {}


@contextlib.contextmanager
def cache_for(plan, *, actual=False):
    args = expected(plan)
    catalog, manifest = load(args['catalog_id'])
    import apt_pkg

    with tempfile.TemporaryDirectory(prefix='mano-apt-') as temporary:
        root = Path(temporary)
        prepare_apt_root(root, catalog=catalog)
        # This is a fresh fixed worker process, just like the forecast worker.
        # Configuration.clear requires a key; it is not dict.clear(). Set the
        # private tree before initialization instead of reading host APT config.
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
        # Match the forecast worker: rootdir also reinitializes libapt's system
        # object, rather than merely changing configuration strings after init.
        cache = apt.Cache(progress=apt.progress.base.OpProgress(), rootdir=str(root), memonly=True)
        if actual:
            cache.close()
            apt_pkg.config.set('Dir::State::status', '/var/lib/dpkg/status')
            apt_pkg.config.set('Dir::State::extended_states', '/var/lib/apt/extended_states')
            apt_pkg.init_system()
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
    global STAGE
    STAGE = 'cache'
    with cache_for(plan) as (cache, _):
        return {row['archive_sha256']: cache[row['name']].candidate.uri
                for row in plan['changes'] if row['operation'] != 'remove'}


def boundary():
    """Fail before effects if the fixed native/namespace boundary is missing."""
    global BOUNDARY_CHECK, BOUNDARY_KERNEL
    BOUNDARY_CHECK = 'identity'
    guard()
    if os.getpid() != 2:
        raise PermissionError('Private package PID namespace required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    BOUNDARY_CHECK = 'native-restrictions'
    BOUNDARY_KERNEL = dict(pid=os.getpid(), NoNewPrivs=int(status['NoNewPrivs']),
                           Seccomp=int(status['Seccomp']))
    if status['NoNewPrivs'].strip() != '1' or status['Seccomp'].strip() != '2':
        raise PermissionError('Native package restrictions absent')
    capabilities = {key: int(status[key].strip(), 16) for key in
                    ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb')}
    securebits = ctypes.CDLL(None, use_errno=True).prctl(27, 0, 0, 0, 0)  # PR_GET_SECUREBITS
    BOUNDARY_CHECK = 'capabilities'
    BOUNDARY_KERNEL.update(capabilities, securebits=securebits)
    if any(value != 0xdb for value in capabilities.values()) or securebits != 43:
        raise PermissionError('Package capability state is not exactly bounded and locked')
    BOUNDARY_CHECK = 'network'
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        connection.close()
        raise PermissionError('Package network socket was not denied')
    BOUNDARY_CHECK = 'protected-objects'
    for index, path in enumerate(('/usr/lib/mano-os/mano_runtime/package_apt.py',
                                  '/sys/fs/cgroup/cgroup.procs', str(STATE_FILE))):
        BOUNDARY_KERNEL['object_index'] = index
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            os.close(fd)
            raise PermissionError('Protected package path opened for writing')
    BOUNDARY_CHECK = 'secrets'
    rows = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    mounts = {row[4]: row[5].split(',') for row in rows}
    BOUNDARY_CHECK = 'credential-mask'
    expected_mask = Path('/usr/lib/mano-os/empty-credential').stat()
    for index, path in enumerate(('/etc/shadow', '/etc/gshadow')):
        info = Path(path).stat()
        BOUNDARY_KERNEL.update(credential_index=index, credential_size=info.st_size,
            credential_regular=int(stat.S_ISREG(info.st_mode)),
            credential_readonly=int('ro' in mounts.get(path, [])),
            credential_matches_asset=int((info.st_dev, info.st_ino) ==
                                        (expected_mask.st_dev, expected_mask.st_ino)))
        if not stat.S_ISREG(info.st_mode) or info.st_size or 'ro' not in mounts.get(path, []):
            raise PermissionError('Credential mask must be an empty read-only regular file')
    run_device = os.stat('/run').st_dev
    # mountinfo includes covered lower mounts. Select the filesystem actually
    # visible through /run, rather than treating a covered host mount as active.
    run_rows = [row for row in rows if row[4] == '/run' and
                os.makedev(*map(int, row[2].split(':'))) == run_device]
    BOUNDARY_CHECK = 'runtime-tmpfs'
    BOUNDARY_KERNEL.update(runtime_mounts=len(run_rows))
    if len(run_rows) != 1 or run_rows[0][run_rows[0].index('-') + 1] != 'tmpfs':
        raise PermissionError('Private runtime tmpfs required')
    BOUNDARY_CHECK = 'approval-ipc'
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(.2)
        try:
            connection.connect('/run/mano-approval/human.sock')
        except OSError as error:
            if error.errno not in {errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM}:
                raise
        else:
            raise PermissionError('Host approval IPC reachable from package worker')
    BOUNDARY_CHECK = 'mount-ancestry'
    if 'ro' not in mounts.get('/', []) or any(path not in mounts for path in
            ('/usr', '/usr/lib', '/usr/bin', '/etc', '/var', '/var/lib')):
        raise PermissionError('Protected mount ancestry absent')
    BOUNDARY_CHECK = 'runtime-infrastructure'
    for path in ('/usr/lib/mano-runtime', '/usr/share/mano-runtime'):
        if Path(path).exists() and 'ro' not in mounts.get(path, []):
            raise PermissionError('Installed mano runtime infrastructure is writable')
    return dict(network_socket_denied=True, protected_code_readonly=True,
                cgroup_control_readonly=True, host_shadow_hidden=True, approval_ipc_hidden=True,
                protected_ancestors_mounted=True, no_new_privileges=True, seccomp_active=True,
                native_stop_authority_readonly=True,
                runtime_infrastructure_readonly=True,
                capabilities=capabilities, securebits=securebits,
                run_device=run_device,
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
    if sys.argv[1:] == ['--commit']:
        STAGE = 'boundary'
        print('MANO_PACKAGE_BOUNDARY=' + canonical(boundary()), flush=True)
    STAGE = 'admission'
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
        commit(plan)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        known = {'PermissionError', 'ValueError', 'Error', 'SystemError', 'TypeError',
                 'AttributeError', 'OSError', 'KeyError', 'RuntimeError', 'TimeoutError'}
        kind = type(error).__name__
        detail = dict(stage=STAGE, error_type=kind if kind in known else 'Unknown')
        if isinstance(error, OSError) and type(error.errno) is int:
            detail['errno'] = error.errno
        messages = {
            'Credential mask must be an empty read-only regular file': 'credential-mask-invalid',
            'Private runtime tmpfs required': 'runtime-tmpfs-required',
            'Host approval IPC reachable from package worker': 'approval-ipc-reachable',
        }
        if str(error) in messages:
            detail['reason'] = messages[str(error)]
        if STAGE == 'boundary':
            detail.update(check=BOUNDARY_CHECK, kernel_state=BOUNDARY_KERNEL)
        print('MANO_PACKAGE_ERROR=' + canonical(detail), file=sys.stderr, flush=True)
        sys.exit(2)
