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
LEGACY_EXCLUDED = (".git", ".mano-write-staging")
EXCLUDED = (*LEGACY_EXCLUDED, ".mano-agent")


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
        or value["excluded_names"] not in (list(EXCLUDED), list(LEGACY_EXCLUDED))
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


def unpack(data):
    """Bounded canonical Git object decoding, never filesystem archive extraction."""
    if not isinstance(data, bytes) or not 10240 <= len(data) <= MAX_ARCHIVE:
        raise ValueError("Bounded checkpoint archive required")
    objects, members = {}, {}
    raw_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as source:
        for member in source:
            if (
                not member.isfile()
                or member.pax_headers
                or member.name in members
                or len(members) >= MAX_FILES + MAX_DIRECTORIES + 4
                or not 0 <= member.size <= MAX_ARCHIVE
            ):
                raise ValueError("Invalid checkpoint archive member")
            content = source.extractfile(member).read()
            members[member.name] = content
            if member.name in {"HEAD", "config", "refs/heads/checkpoint"}:
                continue
            if not re.fullmatch(r"objects/[a-f0-9]{2}/[a-f0-9]{38}", member.name):
                raise ValueError("Unexpected checkpoint object path")
            inflater = zlib.decompressobj()
            raw = inflater.decompress(content, MAX_BYTES + 1024)
            raw_bytes += len(raw)
            if (
                not inflater.eof
                or inflater.unused_data
                or inflater.unconsumed_tail
                or raw_bytes > MAX_BYTES + 131072
            ):
                raise ValueError("Checkpoint decompression quota exhausted")
            oid = member.name[8:10] + member.name[11:]
            if hashlib.sha1(raw, usedforsecurity=False).hexdigest() != oid:
                raise ValueError("Checkpoint Git object hash mismatch")
            header, body = raw.split(b"\0", 1)
            kind, size = header.split(b" ")
            if kind not in {b"blob", b"tree", b"commit"} or size != str(len(body)).encode():
                raise ValueError("Invalid checkpoint Git object header")
            objects[oid] = kind, body
    if set(members) - {"HEAD", "config", "refs/heads/checkpoint"} != {
        "objects/" + oid[:2] + "/" + oid[2:] for oid in objects
    }:
        raise ValueError("Unexpected checkpoint archive entries")
    reference = members.get("refs/heads/checkpoint", b"").decode("ascii")
    if not re.fullmatch(r"[a-f0-9]{40}\n", reference):
        raise ValueError("Invalid checkpoint reference")
    commit = reference.strip()
    if commit not in objects or objects[commit][0] != b"commit":
        raise ValueError("Missing checkpoint commit")
    line = objects[commit][1].split(b"\n", 1)[0]
    if not re.fullmatch(b"tree [a-f0-9]{40}", line):
        raise ValueError("Invalid checkpoint commit tree")
    files, active = {}, set()
    tree_count = source_bytes = 0

    def tree(oid, prefix="", depth=0):
        nonlocal tree_count, source_bytes
        tree_count += 1
        if (
            tree_count > MAX_DIRECTORIES
            or depth > MAX_DEPTH
            or oid in active
            or oid not in objects
            or objects[oid][0] != b"tree"
        ):
            raise ValueError("Invalid cyclic or oversized checkpoint tree")
        active.add(oid)
        body = objects[oid][1]
        while body:
            mode_name, rest = body.split(b"\0", 1)
            if len(rest) < 20:
                raise ValueError("Truncated checkpoint tree entry")
            child, body = rest[:20].hex(), rest[20:]
            mode, leaf = mode_name.split(b" ", 1)
            name = prefix + leaf.decode("utf8")
            path(name)
            if b"/" in leaf:
                raise ValueError("Invalid Git tree leaf")
            if mode == b"40000":
                tree(child, name + "/", depth + 1)
            else:
                if (
                    mode not in {b"100644", b"100755"}
                    or name in files
                    or child not in objects
                    or objects[child][0] != b"blob"
                    or len(files) >= MAX_FILES
                ):
                    raise ValueError("Invalid checkpoint source object")
                blob = objects[child][1]
                source_bytes += len(blob)
                if source_bytes > MAX_BYTES:
                    raise ValueError("Checkpoint source byte quota exhausted")
                files[name] = blob, mode == b"100755"
        active.remove(oid)

    tree(line[5:].decode("ascii"))
    canonical_data, receipt = archive(files)
    if canonical_data != data or receipt["commit"] != commit:
        raise ValueError("Checkpoint archive is not a canonical source export")
    return files
