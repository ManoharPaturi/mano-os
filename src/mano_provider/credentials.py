"""Read fixed systemd credential files, never agent environment secrets."""

import json
import os
import re
import stat
from pathlib import Path

from mano_protocol.actions import model_identifier, unique_object


def private_file(directory, name, maximum):
    if name not in {'config', 'api-key'}:
        raise ValueError('Unknown provider credential')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
            raise ValueError('Unsafe credential directory')
        file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(file)
            checks = {
                'credential-file-type': stat.S_ISREG(info.st_mode),
                'credential-file-owner': info.st_uid in {0, os.geteuid()},
                'credential-file-mode': stat.S_IMODE(info.st_mode) in {0o400, 0o600},
                'credential-file-links': info.st_nlink == 1,
                'credential-file-size': 1 <= info.st_size <= maximum,
            }
            for code, valid in checks.items():
                if not valid:
                    raise ValueError(code)
            packet = os.read(file, maximum + 1)
            if len(packet) != info.st_size:
                raise ValueError('Provider credential changed')
            return packet
        finally:
            os.close(file)
    finally:
        os.close(fd)


def directory():
    base = Path(os.environ.get('CREDENTIALS_DIRECTORY', ''))
    if (not base.is_absolute() or base.parent != Path('/run/credentials')
            or not base.name.startswith('mano-provider@') or not base.name.endswith('.service')):
        raise ValueError('Fixed service credential directory required')
    for parent in base.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted credential ancestor')
    return base


def load():
    base = directory()
    config = json.loads(private_file(base, 'config', 4096).decode('utf8'),
                        object_pairs_hook=unique_object)
    if (not isinstance(config, dict)
            or set(config) != {'provider', 'model', 'max_output_tokens', 'enabled'}
            or config['provider'] != 'openai' or type(config['enabled']) is not bool
            or type(config['max_output_tokens']) is not int
            or not 16 <= config['max_output_tokens'] <= 8192):
        raise ValueError('Invalid fixed provider policy')
    model_identifier(config['model'])
    key = private_file(base, 'api-key', 4096).decode('ascii')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,4096}', key):
        raise ValueError('Invalid provider credential')
    return config, key

