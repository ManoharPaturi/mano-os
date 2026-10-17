"""Check the root-installed, kernel-enforced provider job profile."""

import os
import pwd
import stat
import sys
from pathlib import Path


def verify_current():
    if sys.platform != 'linux' or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Protected provider requires its Linux service')
    account = pwd.getpwuid(os.geteuid())
    if (account.pw_name != 'mano-provider' or account.pw_gid != os.getegid()
            or account.pw_shell != '/usr/sbin/nologin' or account.pw_dir != '/nonexistent'
            or set(os.getgroups()) - {account.pw_gid}):
        raise ValueError('Protected provider identity absent')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if (any(int(fields[key].strip(), 16)
            for key in ('CapEff', 'CapBnd', 'CapAmb', 'CapPrm', 'CapInh'))
            or fields['NoNewPrivs'].strip() != '1' or fields['Seccomp'].strip() != '2'):
        raise ValueError('Protected provider process restrictions absent')
    name = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup')
                .read_text().splitlines() if line.startswith('0::'))
    prefix = '/mano.slice/mano-core.slice/'
    if (not name.startswith(prefix) or not name.endswith('.service')
            or '/' in name[len(prefix):] or not name[len(prefix):].startswith('mano-provider@')):
        raise ValueError('Protected provider is outside the Stop domain')
    group = Path('/sys/fs/cgroup') / name.lstrip('/')
    info = group.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Provider cgroup is not root managed')
    expected = {'memory.max': '134217728', 'pids.max': '8', 'cpu.max': '20000 100000'}
    if any((group / key).read_text().strip() != value for key, value in expected.items()):
        raise ValueError('Provider resource constraints absent')

