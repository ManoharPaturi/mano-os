"""Human TTY permission selection; fixed native request followed by separate PAM review."""

import argparse
import getpass
import json
import os
import secrets
import sys

from mano_protocol.actions import identifier
from mano_protocol.profiles import configuration, scope

from .approve import approve, rpc

MODES = ('supervised', 'auto', 'full-access')


def profile_packet(prompt_id, request_key, args):
    args = configuration(args)
    return (b'\x01\x08' + identifier(prompt_id).encode('ascii')
            + identifier(request_key).encode('ascii') + bytes([MODES.index(args['mode'])])
            + args['duration_seconds'].to_bytes(2, 'big') + bytes([args['max_actions']])
            + args['max_timeout_seconds'].to_bytes(2, 'big'))


def request_profile(prompt_id, request_key, args):
    result = rpc(profile_packet(prompt_id, request_key, args))
    if (not isinstance(result, dict) or set(result) != {
            'schema_version', 'ok', 'prompt_id', 'task_id', 'approval'}
            or result['schema_version'] != '1.0' or result['ok'] is not True
            or result['prompt_id'] != prompt_id):
        raise ValueError('Invalid profile acknowledgement')
    identifier(result['task_id'])
    pending = result['approval']
    if not isinstance(pending, dict) or set(pending) != {'approval_id', 'state', 'grant_id'}:
        raise ValueError('Invalid profile challenge')
    identifier(pending['approval_id'])
    if pending['state'] == 'approved':
        identifier(pending['grant_id'])
    elif pending['state'] != 'pending' or pending['grant_id'] is not None:
        raise ValueError('Profile challenge unavailable; nothing was activated')
    return result


def read_profile_status(prompt_id):
    result = rpc(b'\x01\x09' + identifier(prompt_id).encode('ascii'))
    if (not isinstance(result, dict) or set(result) != {
            'schema_version', 'ok', 'prompt_id', 'task_id', 'profile'}
            or result['schema_version'] != '1.0' or result['ok'] is not True
            or result['prompt_id'] != prompt_id):
        raise ValueError('Invalid permission status acknowledgement')
    identifier(result['task_id'])
    value = result['profile']
    if (not isinstance(value, dict) or set(value) != {'mode', 'automatic', 'remaining_actions',
            'seconds_remaining', 'max_timeout_seconds', 'scope'}
            or not isinstance(value['mode'], str) or value['mode'] not in MODES
            or type(value['automatic']) is not bool):
        raise ValueError('Invalid permission status')
    for key, maximum in (('remaining_actions', 32), ('seconds_remaining', 900),
                         ('max_timeout_seconds', 300)):
        if type(value[key]) is not int or not 0 <= value[key] <= maximum:
            raise ValueError('Invalid permission bound')
    if ((value['mode'] == 'full-access' and value['seconds_remaining'] > 300)
            or value['scope'] != scope(value['mode'])
            or (value['automatic'] and (not value['remaining_actions']
                or not value['seconds_remaining'] or not value['max_timeout_seconds']))
            or (not value['automatic'] and (value['remaining_actions']
                                            or value['seconds_remaining']))):
        raise ValueError('Inconsistent permission status')
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Review a bounded workspace profile using native PAM')
    parser.add_argument('prompt_id')
    parser.add_argument('mode', choices=MODES, nargs='?')
    parser.add_argument('--status', action='store_true',
                        help='Show availability for new automatic grants')
    parser.add_argument('--duration', type=int, default=60)
    parser.add_argument('--max-actions', type=int, default=4)
    parser.add_argument('--max-timeout', type=int, default=10)
    parser.add_argument('--request-key',
                        help='Reuse the printed key after an uncertain acknowledgement')
    options = parser.parse_args()
    try:
        if (sys.platform != 'linux' or os.getuid() < 1000
                or not os.isatty(0) or not os.isatty(1)):
            raise PermissionError('Native human Linux TTY required')
        identifier(options.prompt_id)
        if options.status:
            if options.mode is not None or options.request_key is not None:
                raise ValueError('Status takes only the prompt identity')
            status = read_profile_status(options.prompt_id)
            print('Automatic availability applies to new grants. '
                  'Issued grants/running work may remain; use Stop to revoke them.')
            print(json.dumps(status, indent=2, sort_keys=True))
            return 0
        key = identifier(options.request_key) if options.request_key else secrets.token_hex(16)
        args = configuration(dict(mode=options.mode, duration_seconds=options.duration,
            max_actions=options.max_actions, max_timeout_seconds=options.max_timeout))
        print('Request key: ' + key, flush=True)
        # No automatic retry or effect replay.
        result = request_profile(options.prompt_id, key, args)
        if result['approval']['state'] == 'approved':
            print('Approval already recorded. Check task status for current authority.')
            return 0
        expected = dict(task_id=result['task_id'], capability='policy.set_profile',
                        args=args, profile_scope=scope(options.mode))
        if not approve(result['approval']['approval_id'], expected=expected):
            print('Cancelled. No profile was activated.')
        return 0
    except (OSError, ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print('Profile request denied or acknowledgement uncertain. '
              'Nothing is retried automatically.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
