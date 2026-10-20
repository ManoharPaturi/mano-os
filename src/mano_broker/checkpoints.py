"""Approved, bounded source-tree capture; no workspace-selected Git execution."""

import hashlib
import json
import os
import stat
import time

from mano_protocol.checkpoints import (
    EXCLUDED,
    MAX_ARCHIVE,
    MAX_BYTES,
    MAX_CHECKPOINTS,
    MAX_DEPTH,
    MAX_DIRECTORIES,
    MAX_ENTRIES,
    MAX_FILES,
    archive,
    metadata,
    path,
)

from .artifacts import identity, seal
from .protocol import ActionRequest, Capability, canonical, identifier
from .state import Denied


def authority(runtime, action_id, expected, now):
    row = runtime.state.db.execute(
        "SELECT a.*,g.revoked,g.epoch,g.expires,g.approved_args_json,"
        "t.boot_id,t.caller_uid,t.human_uid "
        "FROM actions a JOIN grants g ON a.grant_id=g.id "
        "JOIN tasks t ON a.task_id=t.id WHERE a.id=?",
        (action_id,),
    ).fetchone()
    if row is None:
        raise Denied("Unknown workspace checkpoint")
    request = ActionRequest.parse(row["request_json"].encode())
    if (
        row["state"] != expected
        or request.capability != Capability.CHECKPOINT
        or row["revoked"]
        or runtime.state.meta("latched")
        or row["epoch"] != runtime.state.meta("epoch")
        or now >= row["expires"]
        or row["boot_id"] != runtime.boot_id
        or request.args_json != row["approved_args_json"]
    ):
        raise Denied("Workspace checkpoint authority expired or revoked")
    return row, request


def capture(workspace, *, observe, layout=None):
    """Stable individual inode reads and post-walk checks, not an atomic FS snapshot."""
    pins, directories, files = {}, {}, {}
    total = entries = 0
    if layout is not None:
        layout.update(directories=[], excluded=[])
    try:

        def walk(relative, depth):
            nonlocal total, entries
            observe()
            if (
                depth > MAX_DEPTH
                or sum(value[1] is not None for value in directories.values()) >= MAX_DIRECTORIES
            ):
                raise Denied("Checkpoint directory quota exhausted")
            pin = workspace.pin(relative, directory=True)
            pins[relative] = pin
            before = os.fstat(pin.fd)
            directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=pin.fd)
            try:
                names = []
                # scandir is incremental: never allocate an unbounded directory listing.
                with os.scandir(directory) as listing:
                    for item in listing:
                        entries += 1
                        if entries > MAX_ENTRIES:
                            raise Denied("Checkpoint entry quota exhausted")
                        if item.name in EXCLUDED:
                            if layout is not None and item.name != ".mano-write-staging":
                                layout["excluded"].append(
                                    item.name if relative == "." else relative + "/" + item.name
                                )
                            continue
                        name = item.name if relative == "." else relative + "/" + item.name
                        path(name)
                        names.append(item.name)
                names.sort()
            finally:
                os.close(directory)
            directories[relative] = (identity(before), names)
            if layout is not None and relative != ".":
                layout["directories"].append(relative)
            for leaf in names:
                observe()
                name = leaf if relative == "." else relative + "/" + leaf
                info = os.stat(leaf, dir_fd=pin.fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    walk(name, depth + 1)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise Denied("Checkpoint rejects links and special files")
                if len(files) >= MAX_FILES:
                    raise Denied("Checkpoint file quota exhausted")
                source = workspace.pin(name)
                pins[name] = source
                source_before = identity(os.fstat(source.fd))
                fd, receipt = seal(source, maximum=MAX_BYTES - total)
                try:
                    data = os.pread(fd, receipt["size"], 0)
                    if len(data) != receipt["size"]:
                        raise Denied("Incomplete checkpoint file capture")
                finally:
                    os.close(fd)
                current = os.fstat(source.fd)
                if identity(current) != source_before:
                    raise Denied("Checkpoint file changed across sealed capture")
                files[name] = (data, bool(current.st_mode & 0o111))
                total += len(data)
                observe()
                directories[name] = (identity(current), None)

        walk(".", 0)
        for name, (expected, names) in directories.items():
            observe()
            with workspace.pin(name, directory=names is not None) as current:
                if identity(os.fstat(current.fd)) != expected:
                    raise Denied("Checkpoint source changed or was replaced during capture")
        observe()
        if layout is not None:
            layout["directories"].sort()
            layout["excluded"].sort()
        return archive(files)
    finally:
        for pin in pins.values():
            pin.close()


def execute(runtime, action_id, *, clock=None):
    clock = clock or time.monotonic
    state, registry = runtime.state, runtime.registry
    identifier(action_id)
    try:
        row, request = authority(runtime, action_id, "intent", clock())
        prepared = registry.leases.get(action_id)
        resource = registry.resources.get(request.resource_id)
        if (
            prepared is None
            or prepared.closed
            or prepared.started
            or resource is None
            or resource.task_id != request.task_id
            or (resource.caller_uid, resource.human_uid) != (row["caller_uid"], row["human_uid"])
            or resource.boot_id != runtime.boot_id
            or prepared.resource_id != request.resource_id
            or set(prepared.descriptors) != {"root"}
        ):
            raise Denied("Exact live workspace descriptor custody required")
        root = prepared.descriptors["root"]
        if root.fd < 0 or (root.device, root.inode) != (
            resource.workspace.device,
            resource.workspace.inode,
        ):
            raise Denied("Checkpoint root pin differs from approved workspace")
        used = state.db.execute(
            "SELECT count(*),coalesce(sum(length(data)),0) FROM checkpoints"
        ).fetchone()
        if used[0] >= MAX_CHECKPOINTS or used[1] + MAX_ARCHIVE > MAX_CHECKPOINTS * MAX_ARCHIVE:
            raise Denied("Checkpoint retention quota exhausted; no automatic deletion")
        disk = os.statvfs(state.directory)
        if disk.f_bavail * disk.f_frsize < 64 * 1024**2 + 3 * MAX_ARCHIVE:
            raise Denied("Insufficient free space for checkpoint and durable journal")
        registry.start(state, action_id, now=clock(), boot_id=runtime.boot_id)
        deadline = clock() + 5

        def observe():
            runtime.sync_stop()
            authority(runtime, action_id, "executing", clock())
            if clock() >= deadline:
                raise Denied("Checkpoint capture deadline exhausted")

        captured_layout = dict(directories=[], excluded=[])
        data, receipt = capture(resource.workspace, observe=observe, layout=captured_layout)
        observe()
        receipt.update(task_id=request.task_id, action_id=action_id, boot_id=runtime.boot_id)
        metadata(receipt)
        with state.transaction():
            observe()
            state.db.execute(
                "INSERT INTO checkpoints VALUES(?,?,?)", (action_id, canonical(receipt), data)
            )
            state.db.execute(
                "INSERT INTO checkpoint_layouts VALUES(?,?)",
                (action_id, canonical(captured_layout)),
            )
            state.transition(action_id, "done", exit_code=0)
            state.event(action_id, "git-workspace-checkpoint-captured", receipt)
    finally:
        row = state.db.execute("SELECT state FROM actions WHERE id=?", (action_id,)).fetchone()
        if row and row["state"] in {"intent", "executing"}:
            state.transition(action_id, "failed" if row["state"] == "intent" else "unknown")
        registry.release(action_id)


def read(state, *, task_id, action_id, caller_uid, boot_id):
    identifier(task_id)
    identifier(action_id)
    row = state.db.execute(
        "SELECT c.*,a.request_json,a.state FROM checkpoints c "
        "JOIN actions a ON c.action_id=a.id JOIN tasks t ON a.task_id=t.id "
        "WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=?",
        (action_id, task_id, caller_uid, boot_id),
    ).fetchone()
    if (
        row is None
        or row["state"] != "done"
        or ActionRequest.parse(row["request_json"].encode(),
                               historical_checkpoint=True).capability != Capability.CHECKPOINT
    ):
        raise Denied("No owned current-boot checkpoint")
    receipt = metadata(json.loads(row["metadata_json"]))
    if (
        receipt["task_id"] != task_id
        or receipt["action_id"] != action_id
        or receipt["boot_id"] != boot_id
        or len(row["data"]) != receipt["archive_bytes"]
        or hashlib.sha256(row["data"]).hexdigest() != receipt["sha256"]
    ):
        raise Denied("Checkpoint custody integrity mismatch")
    return receipt, row["data"]
