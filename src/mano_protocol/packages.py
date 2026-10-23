"""Explicit Debian package forecasts; a plan never grants installation authority."""

import hashlib
import re

from .actions import canonical, text

MAX_NAMES = 8
MAX_CHANGES = 64
MAX_RESULT = 49152
TIMEOUT = 60


def digest(value):
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value):
        raise ValueError("Exact package catalog digest required")
    return value


def name(value):
    if not isinstance(value, str) or not re.fullmatch("[a-z0-9][a-z0-9+.-]{1,63}", value):
        raise ValueError("A canonical Debian package name is required")
    return value


def arguments(value):
    if not isinstance(value, dict) or set(value) != {"names", "catalog_id"}:
        raise ValueError("Only exact package names and a catalog ID are allowed")
    names = value["names"]
    if (
        not isinstance(names, list)
        or not 1 <= len(names) <= MAX_NAMES
        or any(name(item) != item for item in names)
        or names != sorted(set(names))
    ):
        raise ValueError("Bounded sorted unique package names required")
    digest(value["catalog_id"])
    return value


def version(value):
    if value is not None:
        text(value, 256)
        if not re.fullmatch("[A-Za-z0-9.+:~_-]+", value):
            raise ValueError("Invalid package version")
    return value


def count(value, *, signed=False):
    if type(value) is not int or not (-(2**40) if signed else 0) <= value <= 2**40:
        raise ValueError("Invalid bounded package byte accounting")
    return value


def result(value, *, expected):
    arguments(expected)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "names",
            "catalog_id",
            "status_sha256",
            "solver",
            "requested",
            "changes",
            "download_bytes",
            "net_installed_bytes",
            "peak_space_bytes",
            "free_space_bytes_at_catalog",
            "catalog_expires_at",
            "install_authorized",
            "effect_verified",
            "host_archive_cache_considered",
            "network_used",
            "maintainer_scripts_executed",
        }
        or value["schema_version"] != "1.0"
        or value["names"] != expected["names"]
        or value["catalog_id"] != expected["catalog_id"]
        or any(
            value[field] is not False
            for field in (
                "install_authorized",
                "effect_verified",
                "host_archive_cache_considered",
                "network_used",
                "maintainer_scripts_executed",
            )
        )
        or value["peak_space_bytes"] is not None
    ):
        raise ValueError("Package forecast scope or authority changed")
    digest(value["status_sha256"])
    text(value["solver"], 128)
    count(value["download_bytes"])
    count(value["net_installed_bytes"], signed=True)
    count(value["free_space_bytes_at_catalog"])
    count(value["catalog_expires_at"])
    requested = value["requested"]
    if not isinstance(requested, list) or len(requested) != len(expected["names"]):
        raise ValueError("Incomplete requested package accounting")
    for row, package in zip(requested, expected["names"], strict=True):
        if not isinstance(row, dict) or set(row) != {"name", "installed", "candidate"}:
            raise ValueError("Invalid requested package state")
        if row["name"] != package or version(row["candidate"]) is None:
            raise ValueError("Requested package/candidate changed")
        version(row["installed"])
    changes = value["changes"]
    if not isinstance(changes, list) or len(changes) > MAX_CHANGES:
        raise ValueError("Package change set exceeds budget")
    observed = []
    for row in changes:
        if not isinstance(row, dict) or set(row) != {
            "name",
            "operation",
            "installed",
            "candidate",
            "architecture",
            "archive_sha256",
            "download_bytes",
            "installed_bytes",
        }:
            raise ValueError("Invalid package change record")
        observed.append(name(row["name"]))
        if row["operation"] not in {"install", "upgrade", "downgrade", "reinstall", "remove"}:
            raise ValueError("Unknown package operation")
        version(row["installed"])
        version(row["candidate"])
        if row["architecture"] not in {"amd64", "all"}:
            raise ValueError("Unsupported package architecture")
        if row["operation"] == "remove":
            if (
                row["candidate"] is not None
                or row["archive_sha256"] is not None
                or row["installed"] is None
                or row["download_bytes"] != 0
            ):
                raise ValueError("Removal cannot carry a replacement")
        else:
            if row["candidate"] is None:
                raise ValueError("Candidate version required")
            digest(row["archive_sha256"])
            installed, candidate = row["installed"], row["candidate"]
            if (
                (row["operation"] == "install" and installed is not None)
                or (row["operation"] == "reinstall" and installed != candidate)
                or (
                    row["operation"] in {"upgrade", "downgrade"}
                    and (installed is None or installed == candidate)
                )
            ):
                raise ValueError("Package operation contradicts its version transition")
        count(row["download_bytes"])
        count(row["installed_bytes"])
    if observed != sorted(set(observed)) or len(canonical(value).encode()) > MAX_RESULT:
        raise ValueError("Duplicate, unsorted or excessive package result")
    if sum(row["download_bytes"] for row in changes) != value["download_bytes"]:
        raise ValueError("Package archive sizes do not match the forecast total")
    by_name = {row["name"]: row for row in changes}
    for row in requested:
        change = by_name.get(row["name"])
        if change is None:
            if row["installed"] != row["candidate"]:
                raise ValueError("Requested version transition missing from changes")
        elif (
            change["operation"] == "remove"
            or change["installed"] != row["installed"]
            or change["candidate"] != row["candidate"]
        ):
            raise ValueError("Requested package contradicts the final change set")
    return value


def result_digest(value, *, expected):
    return hashlib.sha256(canonical(result(value, expected=expected)).encode()).hexdigest()


def install_review(value, *, expected, task_id, resource_id, action_id, plan_sha256, boot_id):
    fields = {
        'schema_version', 'task_id', 'resource_id', 'action_id', 'boot_id', 'epoch',
        'native_generation', 'plan_sha256', 'plan', 'issued_at', 'expires_at',
        'catalog_inputs_current_at_review', 'package_locks_held',
        'root_resolution_verified', 'fresh_apply_approval_required',
        'install_authorized', 'apply_available', 'current_applicability_verified',
        'external_effects_reversible', 'review_sha256',
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value['schema_version'] != '1.0'
            or any(value[k] != v for k, v in dict(task_id=task_id, resource_id=resource_id,
                   action_id=action_id, boot_id=boot_id, plan_sha256=plan_sha256).items())
            or any(value[k] is not False for k in (
                'package_locks_held', 'root_resolution_verified', 'install_authorized',
                'apply_available', 'current_applicability_verified', 'external_effects_reversible'))
            or value['catalog_inputs_current_at_review'] is not True
            or value['fresh_apply_approval_required'] is not True):
        raise ValueError('Package installation review scope or authority changed')
    count(value['epoch'])
    if type(value['native_generation']) is not int or not -1 <= value['native_generation'] <= 2**40:
        raise ValueError('Invalid review Stop generation')
    count(value['issued_at'])
    count(value['expires_at'])
    if not 0 < value['expires_at'] - value['issued_at'] <= 60:
        raise ValueError('Invalid review lifetime')
    plan = result(value['plan'], expected=expected)
    if value['expires_at'] > plan['catalog_expires_at']:
        raise ValueError('Review outlives its package catalog')
    if result_digest(value['plan'], expected=expected) != digest(plan_sha256):
        raise ValueError('Review differs from the captured package forecast')
    body = {k: v for k, v in value.items() if k != 'review_sha256'}
    if hashlib.sha256(canonical(body).encode()).hexdigest() != digest(value['review_sha256']):
        raise ValueError('Package review digest changed')
    return value


def receipt(value, *, expected, metadata):
    from .terminal_output import metadata as parse

    plan = result(value, expected=expected)
    parse(metadata, task_id=metadata["task_id"], action_id=metadata["action_id"])
    if metadata["return_code"] != 0 or metadata["reason"] != "completed":
        raise ValueError("Only a completed forecast has a custody receipt")
    return dict(
        task_id=metadata["task_id"],
        action_id=metadata["action_id"],
        boot_id=metadata["boot_id"],
        catalog_id=plan["catalog_id"],
        names=plan["names"],
        sha256=result_digest(plan, expected=expected),
        download_bytes=plan["download_bytes"],
        net_installed_bytes=plan["net_installed_bytes"],
        peak_space_bytes=None,
        install_authorized=False,
        effect_verified=False,
        current_applicability_verified=False,
    )


def apply_arguments(value):
    from .actions import identifier

    if not isinstance(value, dict) or set(value) != {'forecast_action_id', 'plan_sha256'}:
        raise ValueError('Only an owned forecast action and its exact digest may be applied')
    identifier(value['forecast_action_id'])
    digest(value['plan_sha256'])
    return value
