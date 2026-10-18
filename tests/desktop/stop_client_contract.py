"""Root-only disposable mount-namespace tests for native human Stop replies."""

import array
import json
import os
import pwd
import socket
import subprocess
import time
from pathlib import Path


def main():
    assert os.geteuid() == 0
    assert Path('/etc/mano-lab-disposable').read_text().strip() == 'mano-phase0-ci'
    assert subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in {
        'kvm', 'qemu'}
    assert Path('/proc/self/ns/mnt').readlink() != Path('/proc/1/ns/mnt').readlink()
    directory = Path('/run/mano-stopd')
    directory.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', str(directory)],
                   timeout=5, check=True)
    path = directory / 'human.sock'
    directory.chmod(0o777)  # Isolated fixture mount only.
    passed = []
    try:
        for case in ('valid', 'denied', 'extra', 'truncated', 'rights', 'wrong_sender',
                     'wrong_creator', 'timeout'):
            if case == 'wrong_creator':
                os.seteuid(pwd.getpwnam('mano-human').pw_uid)
            try:
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                listener.bind(str(path))
                listener.listen(1)
            finally:
                os.seteuid(0)
            with listener:
                path.chmod(0o666)  # Fixture-only; real socket stays human-group restricted.
                child = os.fork()
                if child == 0:
                    try:
                        with listener.accept()[0] as connection:
                            packet = connection.recv(2)
                            if case == 'wrong_creator':
                                assert packet == b''
                                os._exit(0)
                            assert packet == b'S'
                            if case == 'timeout':
                                time.sleep(3)
                            elif case == 'wrong_sender':
                                account = pwd.getpwnam('mano-agent')
                                os.setgroups([])
                                os.setgid(account.pw_gid)
                                os.setuid(account.pw_uid)
                                connection.send(b'stopped')
                            elif case == 'rights':
                                fd = os.open('/dev/null', os.O_RDONLY)
                                connection.sendmsg([b'stopped'], [(socket.SOL_SOCKET,
                                    socket.SCM_RIGHTS, array.array('i', [fd]))])
                                os.close(fd)
                            else:
                                connection.send({'valid': b'stopped', 'denied': b'denied',
                                    'extra': b'stopped\n', 'truncated': b'stopped'*20}[case])
                        os._exit(0)
                    except BaseException:
                        os._exit(125)
                try:
                    result = subprocess.run(['/usr/sbin/runuser', '-u', 'mano-human', '--',
                        '/usr/libexec/mano-stop'], capture_output=True, text=True, timeout=5)
                    assert result.returncode == (0 if case == 'valid' else 1), (case, result)
                    assert ('Emergency Stop acknowledged' in result.stdout) == (case == 'valid')
                finally:
                    _, status = os.waitpid(child, 0)
                    assert os.waitstatus_to_exitcode(status) == 0, case
                    path.unlink()
            passed.append(case)
        print(json.dumps(dict(reply_cases=passed, physical_input_provenance=None)))
    finally:
        subprocess.run(['umount', str(directory)], timeout=5, check=True)


if __name__ == '__main__':
    main()
