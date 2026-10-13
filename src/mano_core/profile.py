"""Startup checks for the root-installed, OS-enforced core process profile."""

import grp
import os
import pwd
import stat
import sys
from pathlib import Path


class ProfileDenied(ValueError):
    pass


def verify_current():
    if sys.platform != 'linux' or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise ProfileDenied('Core requires its unprivileged Linux service')
    account = pwd.getpwuid(os.geteuid())
    request_group = grp.getgrnam('mano-request').gr_gid
    if (not account.pw_name.startswith('mano-task-') or account.pw_uid < 1000
            or account.pw_gid != os.getegid() or account.pw_shell != '/usr/sbin/nologin'
            or account.pw_dir != '/nonexistent'
            or set(os.getgroups()) - {account.pw_gid, request_group}):
        raise ProfileDenied('Core requires a managed task identity')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if (any(int(fields[key].strip(), 16)
            for key in ('CapEff', 'CapBnd', 'CapAmb', 'CapPrm', 'CapInh'))
            or fields['NoNewPrivs'].strip() != '1' or fields['Seccomp'].strip() != '2'):
        raise ProfileDenied('Core process restrictions absent')
    group_name = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup')
                      .read_text().splitlines() if line.startswith('0::'))
    prefix = '/mano.slice/mano-core.slice/'
    if (not group_name.startswith(prefix) or not group_name.endswith('.service')
            or '/' in group_name[len(prefix):]
            or not group_name[len(prefix):].startswith('mano-agent-step-')):
        raise ProfileDenied('Core process is outside the managed slice')
    group = Path('/sys/fs/cgroup') / group_name.lstrip('/')
    info = group.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ProfileDenied('Core cgroup is not root managed')
    expected = {'memory.max': '268435456', 'pids.max': '32', 'cpu.max': '50000 100000'}
    if any((group / key).read_text().strip() != value for key, value in expected.items()):
        raise ProfileDenied('Core resource constraints absent')
