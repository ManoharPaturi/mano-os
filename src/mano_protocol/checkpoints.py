"""Git-compatible source checkpoints; repository metadata is never authority."""

import hashlib
import io
import re
import tarfile
import zlib
from pathlib import PurePosixPath

from .actions import relative_path

MAX_FILES = 64
MAX_DIRECTORIES = 16
MAX_ENTRIES = 128
MAX_DEPTH = 12
MAX_BYTES = 2 * 1024**2
MAX_ARCHIVE = 4 * 1024**2
MAX_CHECKPOINTS = 8
EXCLUDED = (".git", ".mano-write-staging")


def path(value):
    relative_path(value)
    parts = PurePosixPath(value).parts
    if (
        not parts
        or value == "."
        or len(parts) > MAX_DEPTH
        or len(value.encode()) > 512
        or any(part in EXCLUDED or len(part.encode()) > 255 for part in parts)
    ):
        raise ValueError("Unsupported checkpoint source path")
    return value


def archive(files):
    """Encode raw bytes as Git objects without invoking Git/config/hooks/filters."""
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise ValueError("Checkpoint file quota exhausted")
    objects, root = {}, {}
    total = 0

    def object_id(kind, body):
        raw = kind.encode() + b" " + str(len(body)).encode() + b"\0" + body
        # SHA-1 is Git's interoperable identifier, not our integrity boundary.
        oid = hashlib.sha1(raw, usedforsecurity=False).hexdigest()
        if oid in objects and objects[oid] != raw:
            raise ValueError("Git object identity collision")
        objects[oid] = raw
        return oid

    for name, entry in sorted(files.items()):
        path(name)
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], bytes)
            or type(entry[1]) is not bool
        ):
            raise ValueError("Exact checkpoint bytes and executable bit required")
        data, executable = entry
        total += len(data)
        if total > MAX_BYTES:
            raise ValueError("Checkpoint byte quota exhausted")
        parts = PurePosixPath(name).parts
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError("Conflicting checkpoint file and directory")
        if parts[-1] in node:
            raise ValueError("Conflicting checkpoint directory and file")
        node[parts[-1]] = ("100755" if executable else "100644", object_id("blob", data))

    def tree(node):
        entries = []
        for name, value in node.items():
            mode, oid = ("40000", tree(value)) if isinstance(value, dict) else value
            sort_key = name.encode() + (b"/" if mode == "40000" else b"")
            entries.append(
                (sort_key, mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
            )
        return object_id("tree", b"".join(value for _, value in sorted(entries)))

    tree_id = tree(root)
    body = (
        f"tree {tree_id}\nauthor mano checkpoint <checkpoint@mano.invalid> 0 +0000\n"
        "committer mano checkpoint <checkpoint@mano.invalid> 0 +0000\n\n"
        "Approved source workspace checkpoint\n"
    ).encode()
    commit = object_id("commit", body)
    content = {
        "HEAD": b"ref: refs/heads/checkpoint\n",
        "refs/heads/checkpoint": (commit + "\n").encode(),
        "config": b"[core]\nrepositoryformatversion = 0\nbare = true\n",
    }
    for oid, raw in objects.items():
        content["objects/" + oid[:2] + "/" + oid[2:]] = zlib.compress(raw)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name, data in sorted(content.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            output.addfile(info, io.BytesIO(data))
    data = buffer.getvalue()
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Checkpoint archive quota exhausted")
    return data, dict(
        commit=commit,
        tree=tree_id,
        files=len(files),
        source_bytes=total,
        archive_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        excluded_names=list(EXCLUDED),
        git_metadata_imported=False,
        atomic_filesystem_snapshot=False,
        effect_verified=False,
    )


def metadata(value):
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "commit",
            "tree",
            "files",
            "source_bytes",
            "archive_bytes",
            "sha256",
            "excluded_names",
            "git_metadata_imported",
            "atomic_filesystem_snapshot",
            "effect_verified",
            "task_id",
            "action_id",
            "boot_id",
        }
        or value["excluded_names"] != list(EXCLUDED)
        or value["git_metadata_imported"] is not False
        or value["atomic_filesystem_snapshot"] is not False
        or value["effect_verified"] is not False
    ):
        raise ValueError("Invalid checkpoint provenance")
    from .actions import identifier, text

    identifier(value["task_id"])
    identifier(value["action_id"])
    text(value["boot_id"], 128)
    for key, size in (("commit", 40), ("tree", 40), ("sha256", 64)):
        if not isinstance(value[key], str) or not re.fullmatch(f"[a-f0-9]{{{size}}}", value[key]):
            raise ValueError("Invalid checkpoint object identity")
    for key, maximum in (
        ("files", MAX_FILES),
        ("source_bytes", MAX_BYTES),
        ("archive_bytes", MAX_ARCHIVE),
    ):
        if type(value[key]) is not int or not 0 <= value[key] <= maximum:
            raise ValueError("Invalid checkpoint byte/file accounting")
    return value
