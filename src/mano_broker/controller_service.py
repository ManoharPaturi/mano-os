"""Fixed credentialed recurring controller entry point; no stdin/argv task input."""

import errno
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

from mano_protocol.credential_files import private_file
from mano_protocol.provider import configuration, decode

from .controller import run_cycle
from .protocol import canonical

DIRECTORY = Path('/run/credentials/mano-controller.service')
ROOT_CAPABILITIES = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 6) | (1 << 7)


def parse(packet):
    value = decode(packet, 4096)
    if (not isinstance(value, dict) or set(value) != {
            'schema_version', 'enabled', 'model', 'max_output_tokens'}
            or value['schema_version'] != '1.0' or type(value['enabled']) is not bool):
        raise ValueError('Invalid Root controller policy')
    if not value['enabled']:
        if value['model'] is not None or value['max_output_tokens'] is not None:
            raise ValueError('Disabled controller must have no model metadata')
        return None
    configuration(value['model'], value['max_output_tokens'])
    return dict(model=value['model'], max_output_tokens=value['max_output_tokens'])


class ControllerProfileDenied(ValueError):
    pass


def verify_current():
    if sys.platform != 'linux' or (os.getuid(), os.geteuid(), os.getegid()) != (0, 0, 0):
        raise ControllerProfileDenied('Installed Root controller service required')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if (fields['NoNewPrivs'].strip() != '1' or fields['Seccomp'].strip() != '2'
            or any(int(fields[key].strip(), 16) != ROOT_CAPABILITIES
                   for key in ('CapEff', 'CapPrm', 'CapBnd'))
            or any(int(fields[key].strip(), 16) for key in ('CapAmb', 'CapInh'))):
        raise ControllerProfileDenied('Root controller restrictions absent')
    group = next(line.split('::', 1)[1]
                 for line in Path('/proc/self/cgroup').read_text().splitlines()
                 if line.startswith('0::'))
    if group != '/mano.slice/mano-core.slice/mano-controller.service':
        raise ControllerProfileDenied('Controller must share native Stop domain')
    for path in ('/etc/mano/controller.json', '/etc/mano/human.uid', '/etc/pam.d/mano-approve'):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise ControllerProfileDenied(
                    'Controller policy mount is not demonstrably read-only') from error
        else:
            os.close(fd)  # No write/truncate is attempted, even on profile failure.
            raise ControllerProfileDenied('Controller can open protected policy for writing')
    try:
        fd = os.open('/etc/mano/credentials/openai', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        if error.errno not in {errno.ENOENT, errno.EACCES, errno.ENOTDIR}:
            raise ControllerProfileDenied(
                'Unexpected provider credential isolation failure') from error
    else:
        os.close(fd)  # Never read credential bytes, even if isolation is broken.
        raise ControllerProfileDenied('Controller can open provider key source')
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno not in {errno.EPERM, errno.EAFNOSUPPORT}:
            raise ControllerProfileDenied('Unexpected controller network restriction') from error
    else:
        connection.close()  # No connect, DNS or network traffic.
        raise ControllerProfileDenied('Controller Internet socket creation is not denied')



def load():
    verify_current()
    if os.environ.get('CREDENTIALS_DIRECTORY') != str(DIRECTORY):
        raise ValueError('Fixed Root controller credential required')
    for parent in DIRECTORY.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted controller credential ancestor')
    return parse(private_file(DIRECTORY, 'config', 4096))


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError('Controller service accepts no arguments')
        policy = load()
        if policy is None:
            result = dict(state='disabled')
        else:
            cycle = run_cycle(**policy)
            result = dict(state='idle' if cycle is None else 'cycle', cycle=cycle)
        print(canonical(dict(schema_version='1.0', ok=True, **result)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration,
            subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, ControllerProfileDenied) else type(error).__name__
        print(canonical(dict(event='controller-service-denied', reason=reason)), file=sys.stderr)
        print(canonical(dict(schema_version='1.0', ok=False, error='uncertain')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
