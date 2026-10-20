"""Explicit destructive source restore plans; no Git or repository execution."""

import hashlib
import re
from pathlib import PurePosixPath

from .actions import canonical, identifier
from .checkpoints import EXCLUDED, MAX_DIRECTORIES, path

MAX_STEPS = 192
MAX_PLAN = 32768


def arguments(value):
    if not isinstance(value, dict) or set(value) != {
        "source_action_id",
        "source_sha256",
        "before_action_id",
        "before_sha256",
        "before_layout_sha256",
    }:
        raise ValueError("Exact saved-source and before-checkpoint references required")
    for key in ("source_action_id", "before_action_id"):
        identifier(value[key])
    for key in ("source_sha256", "before_sha256", "before_layout_sha256"):
        if not isinstance(value[key], str) or not re.fullmatch("[a-f0-9]{64}", value[key]):
            raise ValueError("Exact checkpoint SHA256 required")
    return value


def parents(files):
    return {
        str(parent)
        for name in files
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }


def layout(value):
    if not isinstance(value, dict) or set(value) != {"directories", "excluded"}:
        raise ValueError("Captured checkpoint layout required")
    dirs, excluded = value["directories"], value["excluded"]
    if (
        not isinstance(dirs, list)
        or len(dirs) >= MAX_DIRECTORIES
        or dirs != sorted(set(dirs))
        or not isinstance(excluded, list)
        or len(excluded) > 128
        or excluded != sorted(set(excluded))
    ):
        raise ValueError("Invalid checkpoint layout")
    for name in dirs:
        path(name)
    for name in excluded:
        leaf = PurePosixPath(name)
        if leaf.name not in EXCLUDED or leaf.name == ".mano-write-staging":
            raise ValueError("Unexpected excluded checkpoint entry")
        if str(leaf.parent) != ".":
            path(str(leaf.parent))
    return value


def plan(desired, before, *, before_layout, source_layout=None):
    before_layout = layout(before_layout)
    if source_layout is not None:
        source_layout = layout(source_layout)
    desired_dirs = parents(desired) | set(source_layout["directories"] if source_layout else [])
    before_dirs = set(before_layout["directories"])
    protected = {
        str(parent)
        for name in before_layout["excluded"]
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    if any(name in protected for name in desired):
        raise ValueError("Restore cannot replace a directory containing excluded Git metadata")
    desired_dirs |= protected
    if len(desired_dirs) >= MAX_DIRECTORIES:
        raise ValueError("Restore directory quota exhausted")
    operations = []
    for name in sorted(set(before) - set(desired)):
        operations.append(dict(operation="unlink", path=name))
    for name in sorted(before_dirs - desired_dirs, key=lambda p: (-len(PurePosixPath(p).parts), p)):
        operations.append(dict(operation="rmdir", path=name))
    for name in sorted(desired_dirs - before_dirs, key=lambda p: (len(PurePosixPath(p).parts), p)):
        operations.append(dict(operation="mkdir", path=name))
    for name, (data, executable) in sorted(desired.items()):
        if before.get(name) == (data, executable):
            continue
        operations.append(
            dict(
                operation="publish",
                path=name,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                executable=executable,
            )
        )
    value = dict(
        operations=operations,
        directories=sorted(desired_dirs),
        preserve_excluded=list(EXCLUDED),
        destructive=True,
        atomic_filesystem_restore=False,
    )
    if len(operations) > MAX_STEPS or len(canonical(value).encode()) > MAX_PLAN:
        raise ValueError("Restore plan exceeds approval budget")
    return value
