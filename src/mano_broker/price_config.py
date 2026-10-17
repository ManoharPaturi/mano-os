"""Fixed root-provisioned pricing credential; no caller-supplied policy or keys."""

import os
import pwd
import stat
from pathlib import Path

from mano_protocol.credential_files import private_file
from mano_protocol.provider import configuration, decode

from .model_pricing import PricePolicy
from .state import Denied

DIRECTORY = Path('/run/credentials/mano-broker.service')


def parse(packet, *, wall_time):
    value = decode(packet, 4096)
    if (not isinstance(value, dict)
            or set(value) != {'schema_version', 'provider', 'enabled', 'price'}
            or value['schema_version'] != '1.0' or value['provider'] != 'openai'
            or type(value['enabled']) is not bool):
        raise Denied('Invalid root model pricing policy')
    if not value['enabled']:
        raise Denied('Root model pricing policy disabled')
    if not isinstance(value['price'], dict):
        raise Denied('No verified root model price configuration')
    policy = PricePolicy(**value['price'])
    configuration(policy.model, policy.max_output_tokens)
    policy.quote(dict(provider='openai', model=policy.model,
                      max_output_tokens=policy.max_output_tokens), wall_time=wall_time)
    return policy


def load_policy(*, wall_time):
    broker = pwd.getpwnam('mano-broker')
    if broker.pw_uid == 0 or os.geteuid() != broker.pw_uid:
        raise Denied('Trusted unprivileged broker pricing identity required')
    if os.environ.get('CREDENTIALS_DIRECTORY') != str(DIRECTORY):
        raise Denied('Fixed broker pricing credential directory required')
    for parent in DIRECTORY.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Denied('Untrusted broker credential ancestor')
    return parse(private_file(DIRECTORY, 'pricing', 4096), wall_time=wall_time)
