"""Explicit foreground Root-terminal recovery decisions; never model authority."""

import hashlib
import json
import os
import re
import time

from mano_broker.package_catalog import read, trusted
from mano_protocol.actions import unique_object
from mano_protocol.packages import digest
from mano_runtime import package_attempts as attempts
from mano_runtime import recovery

ACK = 'ACKNOWLEDGE UNKNOWN PACKAGE EFFECTS'
RETIRE = 'ARCHIVE CHECKPOINT METADATA WITHOUT DELETING SNAPSHOT'


def resolution(directory, intent):
    value = json.loads(read(directory / 'operator.json', 4096), object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {
            'schema_version', 'attempt_id', 'request_sha256', 'operator_root_tty',
            'observed_boot_id', 'checkpoint_id', 'status_sha256', 'created_at',
            'automatic_replay_allowed', 'installation_authorized', 'effects_reversed_verified'}
            or value['schema_version'] != '1.0' or value['attempt_id'] != intent['attempt_id']
            or value['request_sha256'] != intent['request_sha256']
            or value['operator_root_tty'] is not True
            or any(value[key] is not False for key in ('automatic_replay_allowed',
                   'installation_authorized', 'effects_reversed_verified'))
            or type(value['created_at']) is not int or value['created_at'] < intent['created_at']
            or not isinstance(value['observed_boot_id'], str)
            or not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',
                                value['observed_boot_id'])):
        raise ValueError('Invalid operator recovery record')
    attempts.identifier(value['checkpoint_id'])
    digest(value['status_sha256'])
    unknown = json.loads(read(directory / 'unknown.json', 4096), object_pairs_hook=unique_object)
    if (not isinstance(unknown, dict) or unknown != dict(schema_version='1.0',
            attempt_id=intent['attempt_id'], state='unknown',
            observed_boot_id=unknown.get('observed_boot_id'), automatic_replay_allowed=False)
            or not isinstance(unknown['observed_boot_id'], str)
            or not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',
                                unknown['observed_boot_id'])):
        raise ValueError('Original unknown outcome must remain intact')
    return value


def acknowledge(attempt_id, checkpoint_id):
    recovery.guard()
    attempts.identifier(attempt_id)
    attempts.identifier(checkpoint_id)
    # Convert a pristine intent to unknown first; malformed/partial data stays blocked.
    rows = attempts.reconcile()
    row = next((row for row in rows if row['intent']['attempt_id'] == attempt_id), None)
    if row is None or row['outcome']['state'] != 'unknown' or 'operator_resolution' in row:
        raise ValueError('One unresolved unknown attempt required')
    with recovery.locked():
        layout = recovery.layout()
        checkpoint = recovery.recovery_record(checkpoint_id)
        source = recovery.STORAGE / str(checkpoint['snapshot_number']) / 'snapshot'
        status = recovery.current_status()
        if (layout['root_uuid'] != checkpoint['layout']['root_uuid']
                or recovery.subvolume(source) != checkpoint['snapshot']
                or recovery.command('/usr/bin/btrfs', 'property', 'get', str(source), 'ro')
                != 'ro=true' or status != checkpoint['status_sha256']
                or hashlib.sha256(recovery.read(source / 'var/lib/dpkg/status',
                                               recovery.MAX_STATUS)).hexdigest() != status):
            raise ValueError('Current clean database must match the selected recovery checkpoint')
        directory = attempts.BASE / attempt_id
        if {p.name for p in directory.iterdir()} != {'intent.json', 'unknown.json'}:
            raise ValueError('Unknown attempt custody changed')
        intent = attempts.record(directory / 'intent.json')
        print('Unknown package attempt:', attempt_id, 'request:', intent['request_sha256'])
        print('Current clean package database:', status, 'checkpoint:', checkpoint_id)
        print('This records your recovery decision, not proof that all payload or external effects '
              'were reversed. The original unknown record stays intact. No automatic replay.')
        if input('Type ' + ACK + ': ').strip() != ACK:
            raise PermissionError('Operator recovery decision not confirmed')
        if recovery.current_status() != status:
            raise ValueError('Package database changed during operator confirmation')
        value = dict(schema_version='1.0', attempt_id=attempt_id,
            request_sha256=intent['request_sha256'], operator_root_tty=True,
            observed_boot_id=attempts.boot(), checkpoint_id=checkpoint_id,
            status_sha256=status, created_at=int(time.time()), automatic_replay_allowed=False,
            installation_authorized=False, effects_reversed_verified=False)
        recovery.save(directory / 'operator.json', value)
        return resolution(directory, intent)


def retire(checkpoint_id):
    recovery.guard()
    attempts.identifier(checkpoint_id)
    with recovery.locked():
        recovery.layout()
        value = recovery.recovery_record(checkpoint_id)
        source = recovery.BASE / (checkpoint_id + '.json')
        trusted(source)
        archive = recovery.BASE / 'retired'
        print('Checkpoint:', checkpoint_id, 'Snapper snapshot:', value['snapshot_number'])
        print('The snapshot stays intact and remains explicitly recoverable. '
              'This only archives active retention metadata.')
        if input('Type ' + RETIRE + ': ').strip() != RETIRE:
            raise PermissionError('Checkpoint retirement not confirmed')
        try:
            archive.mkdir(mode=0o700)
            attempts.sync(archive.parent)
        except FileExistsError:
            pass
        trusted(archive, directory=True)
        if archive.stat().st_mode & 0o777 != 0o700:
            raise ValueError('Private retired checkpoint custody required')
        destination = archive / source.name
        os.link(source, destination, follow_symlinks=False)  # No overwrite, including lost ack.
        attempts.sync(archive)
        source.unlink()  # Metadata remains at the fsynced retained hardlink, snapshot untouched.
        attempts.sync(source.parent)
        if recovery.recovery_record(checkpoint_id) != value:
            raise ValueError('Archived checkpoint custody changed')
        return dict(checkpoint_id=checkpoint_id, metadata_archived=True,
                    snapshot_deleted=False, automatic_replay_allowed=False)
