"""Check the root-installed, kernel-enforced egress job profile."""

import errno
import os
import pwd
import stat
import sys
from pathlib import Path


def verify_current():
    if sys.platform != 'linux' or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Protected egress requires its Linux service')
    account = pwd.getpwuid(os.geteuid())
    if (account.pw_name != 'mano-egress' or account.pw_gid != os.getegid()
            or account.pw_shell != '/usr/sbin/nologin' or account.pw_dir != '/nonexistent'
            or set(os.getgroups()) - {account.pw_gid}):
        raise ValueError('Protected egress identity absent')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if (any(int(fields[key].strip(), 16)
            for key in ('CapEff', 'CapBnd', 'CapAmb', 'CapPrm', 'CapInh'))
            or fields['NoNewPrivs'].strip() != '1' or fields['Seccomp'].strip() != '2'):
        raise ValueError('Protected egress process restrictions absent')
    name = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup')
                .read_text().splitlines() if line.startswith('0::'))
    prefix = '/mano.slice/mano-core.slice/'
    if (not name.startswith(prefix) or not name.endswith('.service')
            or '/' in name[len(prefix):] or not name[len(prefix):].startswith('mano-egress@')):
        raise ValueError('Protected egress is outside the Stop domain')
    group = Path('/sys/fs/cgroup') / name.lstrip('/')
    info = group.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Egress cgroup is not root managed')
    expected = {'memory.max': '67108864', 'pids.max': '4', 'cpu.max': '20000 100000'}
    if any((group / key).read_text().strip() != value for key, value in expected.items()):
        raise ValueError('Egress resource constraints absent')


    try:
        fd = os.open('/etc/mano/credentials/openai', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        if error.errno not in {errno.EACCES, errno.ENOENT, errno.ENOTDIR}:
            raise ValueError('Unexpected egress credential isolation failure') from error
    else:
        os.close(fd)  # Never read key bytes, including on an incorrect installation.
        raise ValueError('Egress role can open provider key source')
