"""Read fixed systemd credential files, never agent environment secrets."""

import json
import os
import re
import stat
from pathlib import Path

from mano_protocol.actions import model_identifier, unique_object
from mano_protocol.credential_files import private_file as read_private_file
from mano_protocol.credential_files import private_mode as private_mode


def private_file(directory, name, maximum):
    if name not in {'config', 'api-key'}:
        raise ValueError('Unknown provider credential')
    return read_private_file(directory, name, maximum)


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


def load_policy():
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
    return config


def load_key():
    key = private_file(directory(), 'api-key', 4096).decode('ascii')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,4096}', key):
        raise ValueError('Invalid provider credential')
    return key


def load():
    return load_policy(), load_key()

