"""Exact dpkg database postconditions, not installation or approval evidence."""

import hashlib
import re
from email.parser import Parser

from mano_protocol.packages import result

MAX_STATUS = 16 * 1024**2


def database(data):
    if not isinstance(data, bytes) or len(data) > MAX_STATUS:
        raise ValueError("Bounded dpkg status bytes required")
    records = {}
    for paragraph in re.split(r"\n\s*\n", data.decode('utf8', errors='strict').strip()):
        if not paragraph:
            continue
        message = Parser().parsestr(paragraph)
        if message.defects:
            raise ValueError("Malformed dpkg status record")
        fields = {}
        for key in ('Package', 'Architecture', 'Status', 'Version'):
            values = message.get_all(key, [])
            if len(values) != 1:
                raise ValueError("Missing or duplicate dpkg identity/state")
            fields[key] = values[0]
        name, arch, state, version = (fields[k] for k in fields)
        if (not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{1,63}', name)
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', arch)
                or not re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,256}', version)
                or len(state.split()) != 3):
            raise ValueError("Invalid dpkg package identity/state")
        wanted, error, status = state.split()
        if (wanted not in {'install', 'hold', 'deinstall', 'purge', 'unknown'}
                or error != 'ok' or status not in {'installed', 'config-files', 'not-installed'}):
            raise ValueError("Unsettled dpkg package state")
        key = (name, arch)
        if key in records:
            raise ValueError("Duplicate dpkg package identity")
        records[key] = (state, version)
    return records


def verify(before, after, plan):
    """Compare every package state/version; do not infer success from exit code."""
    args = {key: plan.get(key) for key in ('names', 'catalog_id')}
    result(plan, expected=args)
    if hashlib.sha256(before).hexdigest() != plan['status_sha256']:
        raise ValueError("Package plan differs from before-checkpoint status")
    old, new = database(before), database(after)
    remaining = set(old) | set(new)
    for change in plan['changes']:
        key = (change['name'], change['architecture'])
        prior, current = old.get(key), new.get(key)
        installed = prior[1] if prior and prior[0].split()[-1] == 'installed' else None
        if installed != change['installed']:
            raise ValueError("Before version differs from package plan")
        if change['operation'] == 'remove':
            if (current is not None
                    and current != ('deinstall ok config-files', change['installed'])):
                raise ValueError("Approved removal did not settle")
        elif current != ('install ok installed', change['candidate']):
            raise ValueError("Approved package version is not fully installed")
        remaining.discard(key)
    if any(old.get(key) != new.get(key) for key in remaining):
        raise ValueError("Package database changed outside the approved change set")
    for requested in plan['requested']:
        candidates = [value for (name, _), value in new.items() if name == requested['name']]
        if (len(candidates) != 1
                or candidates[0] != ('install ok installed', requested['candidate'])):
            raise ValueError("Requested package version postcondition failed")
    return dict(
        before_status_sha256=hashlib.sha256(before).hexdigest(),
        after_status_sha256=hashlib.sha256(after).hexdigest(),
        packages_before=len(old), packages_after=len(new),
        changes_verified=len(plan['changes']), all_package_versions_checked=True,
        execution_authority_verified=False, maintainer_effects_verified=False,
    )
