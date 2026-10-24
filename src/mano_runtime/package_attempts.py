"""Private write-ahead custody for package attempts, outside the recovered root.

This library records uncertainty; it never authorizes, launches or retries an
effect. The future privileged executor must independently verify its approval,
archives, current resolution, locks and Stop state before using an intent.
"""

import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

from mano_broker.package_catalog import read, trusted
from mano_protocol.actions import unique_object
from mano_protocol.packages import digest
from mano_runtime import recovery

BASE = recovery.BASE / "attempts"
MAX_ATTEMPTS = 32


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{32}", value):
        raise ValueError("Exact package attempt identity required")
    return value


def guard():
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Linux Root package-attempt custody required")


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inventory():
    trusted(BASE, directory=True)
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("Private package attempt directory required")
    entries = []
    for path in BASE.iterdir():
        identifier(path.name)
        trusted(path, directory=True)
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise ValueError("Private package attempt custody required")
        entries.append(path.name)
        if len(entries) > MAX_ATTEMPTS:
            raise ValueError("Package attempt retention needs operator review")
    return sorted(entries)


def boot():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch("[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
        raise ValueError("Canonical current boot identity required")
    return value


def record(path):
    value = json.loads(read(path, 4096), object_pairs_hook=unique_object)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "attempt_id",
            "request_sha256",
            "recovery_id",
            "status_sha256",
            "boot_id",
            "created_at",
            "state",
            "installation_authorized",
            "automatic_replay_allowed",
        }
        or value["schema_version"] != "1.0"
        or value["state"] != "intent"
        or type(value["created_at"]) is not int
        or value["created_at"] < 0
        or value["installation_authorized"] is not False
        or value["automatic_replay_allowed"] is not False
        or not isinstance(value["boot_id"], str)
        or not re.fullmatch("[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["boot_id"])
    ):
        raise ValueError("Invalid package attempt intent")
    identifier(value["attempt_id"])
    identifier(value["recovery_id"])
    digest(value["request_sha256"])
    digest(value["status_sha256"])
    if value["attempt_id"] != path.parent.name:
        raise ValueError("Package attempt identity differs from custody")
    return value


def begin(attempt_id, request_sha256, recovery_id):
    """Durably reserve a never-reusable attempt ID before any package effect.

    Root-owned snapshot provenance is required. An intent is not consent or
    evidence that execution started. Even an incomplete directory reserves its ID.
    """
    guard()
    identifier(attempt_id)
    identifier(recovery_id)
    digest(request_sha256)
    recovery.layout()
    with recovery.locked():
        return begin_locked(attempt_id, request_sha256, recovery_id)


def begin_locked(attempt_id, request_sha256, recovery_id):
    """Persist intent without reopening or dropping an existing lock scope."""
    guard()
    recovery.require_locked()
    identifier(attempt_id)
    identifier(recovery_id)
    digest(request_sha256)
    current = recovery.layout()
    saved = recovery.recovery_record(recovery_id)
    status = recovery.current_status()
    if (
        saved["status_sha256"] != status
        or saved["boot_id"] != boot()
        or any(current[key] != saved["layout"][key] for key in current if key != "free_bytes")
    ):
        raise ValueError("Fresh current-boot recovery checkpoint required")
    snapshot = recovery.STORAGE / str(saved["snapshot_number"]) / "snapshot"
    if (
        recovery.subvolume(snapshot) != saved["snapshot"]
        or recovery.command("/usr/bin/btrfs", "property", "get", str(snapshot), "ro") != "ro=true"
        or hashlib.sha256(
            recovery.read(snapshot / "var/lib/dpkg/status", recovery.MAX_STATUS)
        ).hexdigest()
        != status
    ):
        raise ValueError("Recovery checkpoint identity or read-only state changed")
    try:
        BASE.mkdir(mode=0o700)
        sync(BASE.parent)
    except FileExistsError:
        pass
    ensure_available_locked(attempt_id)
    directory = BASE / attempt_id
    directory.mkdir(mode=0o700)  # Never reuse an ID after a lost acknowledgement.
    sync(BASE)
    value = dict(
        schema_version="1.0",
        attempt_id=attempt_id,
        request_sha256=request_sha256,
        recovery_id=recovery_id,
        status_sha256=status,
        boot_id=boot(),
        created_at=int(time.time()),
        state="intent",
        installation_authorized=False,
        automatic_replay_allowed=False,
    )
    recovery.save(directory / "intent.json", value)
    return value


def reconcile():
    """Mark unresolved intents unknown, including after a boot into recovery.

    No attempt is resumed, repaired, cleared or retried. Malformed/partial intent
    or outcome data blocks reconciliation for operator inspection.
    """
    guard()
    recovery.layout()
    with recovery.locked():
        if not BASE.exists() and not BASE.is_symlink():
            return []
        results = []
        for attempt_id in inventory():
            directory = BASE / attempt_id
            if {path.name for path in directory.iterdir()} not in (
                {"intent.json"},
                {"intent.json", "unknown.json"},
                {"intent.json", "verified.json"},
                {"intent.json", "unknown.json", "operator.json"},
            ):
                raise ValueError("Incomplete or foreign package attempt files; inspect custody")
            intent = record(directory / "intent.json")
            if (directory / "verified.json").exists() or (directory / "verified.json").is_symlink():
                results.append(dict(intent=intent,
                    outcome=verified_record(directory / "verified.json", intent)))
                continue
            path = directory / "unknown.json"
            if not path.exists():
                recovery.save(
                    path,
                    dict(
                        schema_version="1.0",
                        attempt_id=attempt_id,
                        state="unknown",
                        observed_boot_id=boot(),
                        automatic_replay_allowed=False,
                    ),
                )
            outcome = json.loads(read(path, 4096), object_pairs_hook=unique_object)
            if (
                not isinstance(outcome, dict)
                or outcome.get("automatic_replay_allowed") is not False
                or outcome
                != dict(
                    schema_version="1.0",
                    attempt_id=attempt_id,
                    state="unknown",
                    observed_boot_id=outcome.get("observed_boot_id"),
                    automatic_replay_allowed=False,
                )
            ):
                raise ValueError("Invalid package attempt outcome")
            observed = outcome["observed_boot_id"]
            if not isinstance(observed, str) or not re.fullmatch(
                "[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", observed
            ):
                raise ValueError("Invalid reconciliation boot identity")
            item = dict(intent=intent, outcome=outcome)
            if (directory / 'operator.json').exists() or (directory / 'operator.json').is_symlink():
                from mano_runtime.package_operator import resolution

                item['operator_resolution'] = resolution(directory, intent)
            results.append(item)
        return results


def verified_record(path, intent):
    """Validate a historical observation; it never proves current boot state."""
    value = json.loads(read(path, 4096), object_pairs_hook=unique_object)
    fields = {"schema_version", "attempt_id", "state", "observed_boot_id",
              "automatic_replay_allowed", "request_sha256", "plan_sha256", "postconditions"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["schema_version"] != "1.0"
            or value["attempt_id"] != intent["attempt_id"]
            or value["state"] != "postconditions-verified"
            or value["observed_boot_id"] != intent["boot_id"]
            or value["request_sha256"] != intent["request_sha256"]
            or value["automatic_replay_allowed"] is not False):
        raise ValueError("Invalid package postcondition record")
    digest(value["plan_sha256"])
    proof = value["postconditions"]
    if (not isinstance(proof, dict) or set(proof) != {
            "before_status_sha256", "after_status_sha256", "packages_before", "packages_after",
            "changes_verified", "all_package_versions_checked", "execution_authority_verified",
            "maintainer_effects_verified"}
            or proof["before_status_sha256"] != intent["status_sha256"]
            or proof["all_package_versions_checked"] is not True
            or proof["execution_authority_verified"] is not False
            or proof["maintainer_effects_verified"] is not False
            or any(type(proof[key]) is not int or not 0 <= proof[key] <= 100000
                   for key in ("packages_before", "packages_after", "changes_verified"))
            or proof["changes_verified"] > 64):
        raise ValueError("Invalid package postcondition proof")
    digest(proof["after_status_sha256"])
    return value


def complete_locked(attempt_id, request_sha256, plan):
    """Durably verify database transitions under an owned backend-held scope.

    This checks package states/versions only, never approval, arbitrary maintainer
    effects, payload contents or the current state after a later recovery boot.
    A published unknown outcome cannot be promoted or automatically retried.
    """
    guard()
    recovery.require_locked()
    identifier(attempt_id)
    digest(request_sha256)
    current_layout = recovery.layout()
    inventory()
    directory = BASE / attempt_id
    if {path.name for path in directory.iterdir()} != {"intent.json"}:
        raise ValueError("Package outcome is already reserved or requires operator recovery")
    intent = record(directory / "intent.json")
    if intent["request_sha256"] != request_sha256 or intent["boot_id"] != boot():
        raise ValueError("Current-boot exact package attempt required")
    checkpoint = recovery.recovery_record(intent["recovery_id"])
    source = recovery.STORAGE / str(checkpoint["snapshot_number"]) / "snapshot"
    if (checkpoint["status_sha256"] != intent["status_sha256"]
            or checkpoint["boot_id"] != intent["boot_id"]
            or any(current_layout[key] != checkpoint["layout"][key]
                   for key in current_layout if key != "free_bytes")
            or recovery.subvolume(source) != checkpoint["snapshot"]
            or recovery.command("/usr/bin/btrfs", "property", "get", str(source), "ro")
            != "ro=true"):
        raise ValueError("Before-checkpoint provenance changed")
    from mano_broker.package_catalog import MAX_STATUS, STATUS
    from mano_protocol.packages import result_digest
    from mano_runtime.package_postconditions import verify

    before = recovery.read(source / "var/lib/dpkg/status", MAX_STATUS)
    current = recovery.current_status()  # Reject an unsettled write-ahead journal.
    after = recovery.read(STATUS, MAX_STATUS)
    proof = verify(before, after, plan)
    if current != proof["after_status_sha256"] or recovery.current_status() != current:
        raise ValueError("Package status changed during postcondition verification")
    value = dict(schema_version="1.0", attempt_id=attempt_id, state="postconditions-verified",
                 observed_boot_id=intent["boot_id"], automatic_replay_allowed=False,
                 request_sha256=request_sha256,
                 plan_sha256=result_digest(plan, expected={key: plan[key]
                                           for key in ("names", "catalog_id")}),
                 postconditions=proof)
    recovery.save(directory / "verified.json", value)
    return verified_record(directory / "verified.json", intent)


def ensure_available_locked(attempt_id):
    """Check history before acquisition/checkpoint effects; no retry or data deletion."""
    guard()
    recovery.require_locked()
    identifier(attempt_id)
    if not BASE.exists() and not BASE.is_symlink():
        return
    existing = inventory()
    if attempt_id in existing:
        raise FileExistsError('Package attempt ID is already reserved')
    if len(existing) >= MAX_ATTEMPTS:
        raise ValueError('Package attempt retention needs operator review')
    for prior in existing:
        directory = BASE / prior
        files = {p.name for p in directory.iterdir()}
        intent = record(directory / 'intent.json')
        if files == {'intent.json', 'verified.json'}:
            verified_record(directory / 'verified.json', intent)
        elif files == {'intent.json', 'unknown.json', 'operator.json'}:
            from mano_runtime.package_operator import resolution

            resolution(directory, intent)
        else:
            raise ValueError('Unresolved package attempt requires operator recovery')
