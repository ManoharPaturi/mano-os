"""Root-UID Stop-domain fixture; guarded disposable CI only, no package apply."""

import errno
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

GROUP = Path('/sys/fs/cgroup/mano.slice/mano-package.slice')
UNIT = 'mano-package-stop-ci.service'
DIRECTORY = Path('/run/mano-package-stop-ci')
SCRIPT = Path('/opt/mano-lab/scripts/probe_root_package_stop.py')


def guard():
    assert sys.platform == 'linux' and os.geteuid() == 0
    assert Path('/etc/mano-lab-disposable').read_text().strip() == 'mano-phase0-ci'
    assert subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in {
        'qemu', 'kvm'}


def worker():
    guard()
    assert DIRECTORY.is_dir() and DIRECTORY.stat().st_uid == 0
    try:
        fd = os.open('/sys/fs/cgroup/cgroup.procs', os.O_WRONLY)
    except OSError as error:
        assert error.errno == errno.EROFS
    else:
        os.close(fd)
        raise AssertionError('Root fixture can open host cgroup control for writing')
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.setsid()
        os.write(write_fd, b'ready')
        os.close(write_fd)
        count = 0
        while True:
            (DIRECTORY / 'root-writer').write_text(str(count))
            count += 1
            time.sleep(.05)
    os.close(write_fd)
    assert os.read(read_fd, 5) == b'ready'
    os.close(read_fd)
    with (DIRECTORY / 'identity.json').open('x') as stream:
        json.dump(dict(parent=os.getpid(), child=child, cgroup_write_denied=True), stream)
    while True:
        time.sleep(1)


def command(*argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          timeout=10, **kwargs)


def wait(check, *, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.02)
    raise AssertionError('Root Stop fixture timed out')


def human_client(actor):
    program = '''import json,sys
from mano_prompt.approve import rpc,rearm_view_packet,rearm_confirmation_packet
body=json.load(sys.stdin)
try:
 packet=(rearm_view_packet() if body['mode']=='rearm_view' else
  rearm_confirmation_packet(body['view'],body['password']))
 result=rpc(packet)
except (PermissionError,ValueError):result={'ok':False}
print(json.dumps(result))
'''
    def call(body):
        return json.loads(command('/usr/sbin/runuser', '-u', actor, '--', 'env', '-i',
            'PATH=/usr/bin:/bin', 'PYTHONPATH=/usr/lib/mano-os',
            'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3', '-c', program,
            input=json.dumps(body)).stdout)
    return call


def run(human, password, broker_pid, launcher_pid, stop_client, *, actor='mano-human'):
    guard()
    from mano_protocol.stop_state import snapshot

    if not snapshot().latched:
        initial = command('/usr/sbin/runuser', '-u', actor, '--', str(stop_client))
        assert 'Emergency Stop acknowledged' in initial.stdout and snapshot().latched
    assert GROUP.is_dir() and 'populated 0' in (GROUP / 'cgroup.events').read_text()
    assert not DIRECTORY.exists()
    DIRECTORY.mkdir(mode=0o700)
    script_sha = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
    systemd_properties = (
        'Type=exec', 'User=root', 'Restart=no', 'NoNewPrivileges=yes',
        'CapabilityBoundingSet=', 'ProtectSystem=strict', 'ProtectHome=yes',
        'PrivateDevices=yes', 'PrivateNetwork=yes', 'PrivateTmp=yes',
        'ProtectControlGroups=yes', 'TemporaryFileSystem=/run',
        'BindPaths=/run/mano-package-stop-ci', 'MemoryMax=64M', 'TasksMax=8',
        'CPUQuota=20%', 'RuntimeMaxSec=60', 'TimeoutStopSec=2',
    )
    argv = ['systemd-run', '--quiet', '--collect', '--unit=' + UNIT,
            '--slice=mano-package.slice']
    for prop in systemd_properties:
        argv += ['--property=' + prop]
    argv += ['/usr/bin/python3', '-I', str(SCRIPT), '--worker']
    descriptors = {}
    authorities = (broker_pid, launcher_pid)
    stop_pid = int(command('systemctl', 'show', 'mano-stopd.service',
                           '--property=MainPID', '--value').stdout)
    try:
        command(*argv)
        def identity():
            try:
                value = json.loads((DIRECTORY / 'identity.json').read_text())
                return value if (DIRECTORY / 'root-writer').exists() else None
            except (FileNotFoundError, ValueError):
                return None
        members = wait(identity)
        assert members['cgroup_write_denied'] is True
        pids = (members['parent'], members['child'])
        assert len(set((*pids, *authorities))) == 4
        assert int(command('systemctl', 'show', UNIT,
                           '--property=MainPID', '--value').stdout) == pids[0]
        observations = {}
        expected_group = '0::/mano.slice/mano-package.slice/' + UNIT
        for pid in pids:
            proc = Path('/proc') / str(pid)
            fields = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines())
            assert fields['Uid'].split() == ['0'] * 4
            assert int(fields['CapEff'].strip(), 16) == 0 and fields['NoNewPrivs'].strip() == '1'
            assert (proc / 'cgroup').read_text().strip() == expected_group
            assert (proc / 'exe').resolve(strict=True) == Path('/usr/bin/python3').resolve()
            assert (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') == [
                b'/usr/bin/python3', b'-I', str(SCRIPT).encode(), b'--worker']
            assert os.readlink(proc / 'ns/net') != os.readlink('/proc/self/ns/net')
            observations[str(pid)] = dict(uid=0, effective_capabilities=0,
                no_new_privs=True, cgroup=expected_group, session=os.getsid(pid))
        assert observations[str(pids[0])]['session'] != observations[str(pids[1])]['session']
        for pid in (*pids, *authorities):
            descriptors[pid] = os.pidfd_open(pid)
            signal.pidfd_send_signal(descriptors[pid], signal.SIGSTOP)
            wait(lambda pid=pid: next(line for line in Path('/proc', str(pid), 'status')
                 .read_text().splitlines() if line.startswith('State:')).split()[1] == 'T')
        for pid in pids:
            proc = Path('/proc') / str(pid)
            assert (proc / 'cgroup').read_text().strip() == expected_group
            assert (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') == [
                b'/usr/bin/python3', b'-I', str(SCRIPT).encode(), b'--worker']
        assert 'populated 0' in Path('/sys/fs/cgroup/mano.slice/mano-core.slice/cgroup.events') \
            .read_text()
        for group in Path('/sys/fs/cgroup/system.slice/mano-launcher.service').glob('task-*'):
            try:
                assert 'populated 0' in (group / 'cgroup.events').read_text()
            except FileNotFoundError:
                pass  # A removed old task is already empty.
        before = (DIRECTORY / 'root-writer').read_bytes()
        view = human(dict(mode='rearm_view'))['view']
        denied = human(dict(mode='rearm_confirm', view=view, password=password))
        assert denied.get('ok') is False and snapshot().latched
        for pid in (*pids, *authorities):
            assert next(line for line in Path('/proc', str(pid), 'status').read_text()
                        .splitlines() if line.startswith('State:')).split()[1] == 'T'
        stopped = command('/usr/sbin/runuser', '-u', actor, '--', str(stop_client))
        assert 'Emergency Stop acknowledged' in stopped.stdout
        wait(lambda: 'populated 0' in (GROUP / 'cgroup.events').read_text())
        for pid in pids:
            wait(lambda pid=pid: bool(select.select([descriptors[pid]], [], [], 0)[0]))
        assert (DIRECTORY / 'root-writer').read_bytes() == before
        for pid in authorities:
            assert next(line for line in Path('/proc', str(pid), 'status').read_text()
                        .splitlines() if line.startswith('State:')).split()[1] == 'T'
        for pid in authorities:
            signal.pidfd_send_signal(descriptors[pid], signal.SIGCONT)
        replay = human(dict(mode='rearm_confirm', view=view, password=password))
        assert replay.get('ok') is False
        fresh = human(dict(mode='rearm_view'))['view']
        rearmed = human(dict(mode='rearm_confirm', view=fresh, password=password))
        assert rearmed['ok'] and rearmed['rearmed'] and not snapshot().latched
        time.sleep(.15)
        assert 'populated 0' in (GROUP / 'cgroup.events').read_text()
        assert (DIRECTORY / 'root-writer').read_bytes() == before
        final = command('/usr/sbin/runuser', '-u', actor, '--', str(stop_client))
        assert 'Emergency Stop acknowledged' in final.stdout and snapshot().latched
        assert int(command('systemctl', 'show', 'mano-stopd.service',
                           '--property=MainPID', '--value').stdout) == stop_pid
        assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == script_sha
        return dict(root_workers=observations, kernel_confirmed_frozen_pids=list(descriptors),
            root_writer_before_sha256=hashlib.sha256(before).hexdigest(),
            root_writer_after_sha256=hashlib.sha256((DIRECTORY / 'root-writer')
                                                   .read_bytes()).hexdigest(),
            root_writer_stopped=True, cgroup_write_denied=True, native_stop_pid=stop_pid,
            stop_cgroup=str(GROUP), root_unit=UNIT,
            root_domain_drained=True, broker_and_launcher_stayed_frozen=True,
            rearm_with_root_members_denied=True, old_rearm_view_denied=True,
            fresh_pam_rearm_after_root_drain=True, no_automatic_restart=True,
            final_generation=snapshot().generation, fixture_script_sha256=script_sha,
            outside_root_observer_pid=os.getpid(), outside_root_observer_untouched=True,
            package_apply_invoked=False, production_maintainer_scripts=False,
            synthetic_os_pam=True, physical_input_provenance=None)
    except BaseException:
        logs = subprocess.run(['journalctl', '-u', UNIT, '--no-pager', '-n', '40'],
                              check=False, capture_output=True, text=True, timeout=5)
        print(logs.stdout, file=sys.stderr)  # This fixed CI fixture receives no secret input.
        raise
    finally:
        for pid in authorities:
            if pid in descriptors and not select.select([descriptors[pid]], [], [], 0)[0]:
                signal.pidfd_send_signal(descriptors[pid], signal.SIGCONT)
        for fd in descriptors.values():
            os.close(fd)
        subprocess.run(['systemctl', 'kill', '--signal=KILL', UNIT], check=False,
                       capture_output=True, timeout=5)
        subprocess.run(['systemctl', 'stop', UNIT], check=False, capture_output=True, timeout=5)


if __name__ == '__main__':
    assert sys.argv[1:] == ['--worker']
    worker()
