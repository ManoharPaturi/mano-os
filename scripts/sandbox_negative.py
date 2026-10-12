import os
import sys
from pathlib import Path

from mano_lab.sandbox import run_probe

w = Path(sys.argv[1])
os.environ.update(
    {
        k: "/run/mano-human/poison"
        for k in [
            "DBUS_SESSION_BUS_ADDRESS",
            "WAYLAND_DISPLAY",
            "DISPLAY",
            "SSH_AUTH_SOCK",
            "GNUPGHOME",
            "PIPEWIRE_REMOTE",
            "WAYLAND_SOCKET",
        ]
    }
)
fd = os.open("/home/mano-agent/.profile", os.O_RDONLY)
os.dup2(fd, 199, inheritable=True)
os.close(fd)
code = r"""
import os, socket
from pathlib import Path
try:
    os.fstat(199)
except OSError:
    pass
else:
    raise AssertionError('Host FD inherited')
p=Path('/workspace/result.txt'); p.write_text('allowed-artifact')
assert p.read_text() == 'allowed-artifact'
for key in ['DBUS_SESSION_BUS_ADDRESS','WAYLAND_DISPLAY','DISPLAY','SSH_AUTH_SOCK',
            'GNUPGHOME','PIPEWIRE_REMOTE','WAYLAND_SOCKET']:
    assert key not in os.environ, key
for target in ['/etc/mano/sentinel','/var/lib/mano-broker/sentinel',
               '/home/mano-human/.bashrc','/run/mano-human','/run/mano-agent',
               '/run/systemd/private','/dev/input','/dev/uinput','/sys/fs/cgroup']:
    assert not Path(target).exists(), target
for target in ['/etc/mano/sentinel','/var/lib/mano-broker/sentinel','/usr/test-escape']:
    try:
        Path(target).write_text('escape')
    except OSError:
        pass
    else:
        raise AssertionError('Host write succeeded: '+target)
s=socket.socket(); s.settimeout(2)
try:
    s.connect(('1.1.1.1',443))
except OSError:
    pass
else:
    raise AssertionError('Unexpected egress')
print('positive artifact plus filesystem/IPC/device/network denial probes passed')
"""
p = run_probe(w, ["/usr/bin/python3", "-c", code])
print(p.stdout)
print(p.stderr)
os.close(199)
assert p.returncode == 0
assert (w / "result.txt").read_text() == "allowed-artifact"
