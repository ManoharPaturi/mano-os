"""Approved bounded atomic publication in an already pinned workspace parent.

Existing writes authorize the directory entry, not mutation of every hardlink to
its old inode. Creation stays no-replace. Uncertain publication is never retried.
"""

import ctypes
import hashlib
import json
import os
import pwd
import stat
import threading
import time
from pathlib import PurePosixPath

from .profiles import Profiles
from .protocol import ActionRequest, Capability, canonical, identifier
from .resources import library
from .state import Denied

STAGING = ".mano-write-staging"
MAX_WRITES = 64


def checked(result):
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def authority(runtime, action_id, expected, now):
    state = runtime.state
    row = state.db.execute(
        "SELECT a.*,g.revoked,g.epoch,g.expires,g.approved_args_json,t.boot_id,t.caller_uid,"
        "t.human_uid FROM actions a JOIN grants g ON a.grant_id=g.id "
        "JOIN tasks t ON a.task_id=t.id WHERE a.id=?",
        (action_id,),
    ).fetchone()
    if row is None:
        raise Denied("Unknown file write")
    request = ActionRequest.parse(row["request_json"].encode())
    if (
        row["state"] != expected
        or request.capability != Capability.WRITE
        or row["revoked"]
        or state.meta("latched")
        or row["epoch"] != state.meta("epoch")
        or now >= row["expires"]
        or row["boot_id"] != runtime.boot_id
        or request.args_json != row["approved_args_json"]
    ):
        raise Denied("File write authority no longer live")
    Profiles(state).require_grant(row["grant_id"], now=now, boot_id=runtime.boot_id)
    return row, request


def execute(runtime, action_id, *, clock=None):
    clock = clock or time.monotonic
    identifier(action_id)
    state, registry = runtime.state, runtime.registry
    stage = target = parent_sync = -1
    token = action_id  # Broker-issued, private directory; no untrusted staging name.
    try:
        row, request = authority(runtime, action_id, "intent", clock())
        prepared = registry.leases.get(action_id)
        resource = registry.resources.get(request.resource_id)
        if (
            prepared is None
            or prepared.closed
            or prepared.started
            or resource is None
            or prepared.resource_id != request.resource_id
            or resource.task_id != request.task_id
            or (resource.caller_uid, resource.human_uid, resource.boot_id)
            != (row["caller_uid"], row["human_uid"], runtime.boot_id)
            or set(prepared.descriptors) not in ({"parent"}, {"parent", "target"})
            or threading.active_count() != 1
        ):
            raise Denied("Live exact write parent lease and single-threaded broker required")
        parent = prepared.descriptors["parent"]
        args = json.loads(request.args_json)
        data = args["text"].encode("utf8")
        leaf = PurePosixPath(args["path"]).name
        create_only = prepared.create_name is not None
        if create_only and (
            prepared.create_name != leaf or set(prepared.descriptors) != {"parent"}
        ):
            raise Denied("Unbound create-only leaf")
        with state.transaction():
            if state.db.execute("SELECT count(*) FROM file_writes").fetchone()[0] >= MAX_WRITES:
                raise Denied("Lifetime write-attempt quota exhausted")
            state.db.execute("INSERT INTO file_writes(action_id) VALUES(?)", (action_id,))
        registry.start(state, action_id, now=clock(), boot_id=runtime.boot_id)
        runtime.sync_stop()
        authority(runtime, action_id, "executing", clock())
        # Keep temporary bytes on the destination filesystem/subvolume. Its
        # private directory FD stays bound if an attacker renames the directory.
        try:
            os.mkdir(STAGING, mode=0o2700, dir_fd=parent.fd)
        except FileExistsError:
            pass
        stage = os.open(
            STAGING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd
        )
        info, directory = os.fstat(stage), os.fstat(parent.fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o777 != 0o700
            or info.st_gid != directory.st_gid
            or info.st_gid != pwd.getpwuid(row["caller_uid"]).pw_gid
        ):
            raise Denied("Private task-group write staging required")
        native = library()
        target = checked(native.mano_create_write_stage(stage, token.encode("ascii")))
        source = os.fstat(target)
        if (
            not stat.S_ISREG(source.st_mode)
            or source.st_uid != os.geteuid()
            or source.st_gid != info.st_gid
            or source.st_nlink != 1
            or stat.S_IMODE(source.st_mode) != 0o660
            or os.get_inheritable(target)
        ):
            raise Denied("Fresh private bounded write inode required")
        offset = 0
        while offset < len(data):
            count = os.write(target, data[offset:])
            if count <= 0:
                raise OSError("Incomplete staged write")
            offset += count
        os.fsync(target)
        os.fsync(stage)
        parent_sync = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent.fd)
        runtime.sync_stop()
        authority(runtime, action_id, "executing", clock())
        checked(
            native.mano_publish_write(
                stage, token.encode("ascii"), parent.fd, leaf.encode("utf8"), int(create_only)
            )
        )
        # From this point a lost reply/failure is an unknown effect. No rollback
        # write, pathname reopening or automatic attempt at another publication.
        os.fsync(parent_sync)
        os.fsync(stage)
        runtime.sync_stop()
        with state.transaction():
            authority(runtime, action_id, "executing", clock())
            metadata = dict(
                task_id=request.task_id,
                action_id=action_id,
                boot_id=runtime.boot_id,
                relative_path=args["path"],
                publication="created" if create_only else "replace-slot",
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                published_device=source.st_dev,
                published_inode=source.st_ino,
                effect_verified=False,
                current_content_verified=False,
            )
            state.db.execute(
                "UPDATE file_writes SET metadata_json=? WHERE action_id=?",
                (canonical(metadata), action_id),
            )
            state.transition(action_id, "done", exit_code=0)
            state.event(
                action_id,
                "workspace-write-published",
                dict(
                    sha256=metadata["sha256"], size=len(data), publication=metadata["publication"]
                ),
            )
    finally:
        # Remove only our private unpublished temporary entry. Keep the empty
        # reserved directory; its pathname may have been moved/replaced by a task.
        if stage >= 0 and target >= 0:
            try:
                os.unlink(token, dir_fd=stage)
            except FileNotFoundError:
                pass
        for fd in (target, stage, parent_sync):
            if fd >= 0:
                os.close(fd)
        row = state.db.execute("SELECT state FROM actions WHERE id=?", (action_id,)).fetchone()
        if row and row["state"] in {"intent", "executing"}:
            state.transition(action_id, "failed" if row["state"] == "intent" else "unknown")
        registry.release(action_id)


def result(state, *, task_id, action_id, caller_uid, boot_id):
    identifier(task_id)
    identifier(action_id)
    row = state.db.execute(
        "SELECT a.state,w.metadata_json FROM file_writes w "
        "JOIN actions a ON w.action_id=a.id JOIN tasks t ON a.task_id=t.id "
        "WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=?",
        (action_id, task_id, caller_uid, boot_id),
    ).fetchone()
    if row is None:
        raise Denied("No owned current-boot write attempt")
    return json.loads(row["metadata_json"]) if row["state"] == "done" else None
