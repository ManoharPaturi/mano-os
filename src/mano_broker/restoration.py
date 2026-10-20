"""Restore approval provenance and deterministic operations; no public source reader."""

import hashlib
import json

from mano_protocol.actions import ActionRequest, Capability, canonical
from mano_protocol.checkpoints import metadata, unpack
from mano_protocol.restoration import arguments, layout, plan

from .state import Denied


def load(state, action_id, sha256, *, human_uid):
    row = state.db.execute(
        "SELECT c.*,a.request_json,a.state,t.human_uid,t.caller_uid,"
        "t.boot_id,t.id AS task_id,t.resource_id,t.classification FROM checkpoints c "
        "JOIN actions a ON c.action_id=a.id JOIN tasks t ON a.task_id=t.id "
        "WHERE a.id=?",
        (action_id,),
    ).fetchone()
    if row is None or row["human_uid"] != human_uid or row["state"] != "done":
        raise Denied("No saved source owned by the approval human")
    request = ActionRequest.parse(row["request_json"].encode())
    receipt = metadata(json.loads(row["metadata_json"]))
    if (
        request.capability != Capability.CHECKPOINT
        or request.task_id != row["task_id"]
        or request.resource_id != row["resource_id"]
        or receipt["task_id"] != row["task_id"]
        or receipt["boot_id"] != row["boot_id"]
        or receipt["action_id"] != action_id
        or receipt["sha256"] != sha256
        or len(row["data"]) != receipt["archive_bytes"]
        or hashlib.sha256(row["data"]).hexdigest() != sha256
    ):
        raise Denied("Saved source provenance or integrity changed")
    files = unpack(row["data"])
    return row, receipt, files


def validate(state, request, *, caller_uid, boot_id):
    if request.capability != Capability.RESTORE:
        return None
    args = arguments(json.loads(request.args_json))
    task = state.db.execute("SELECT * FROM tasks WHERE id=?", (request.task_id,)).fetchone()
    if (
        task is None
        or task["caller_uid"] != caller_uid
        or task["boot_id"] != boot_id
        or task["resource_id"] != request.resource_id
    ):
        raise Denied("Current destination task identity required")
    source, source_receipt, desired = load(
        state, args["source_action_id"], args["source_sha256"], human_uid=task["human_uid"]
    )
    before, before_receipt, previous = load(
        state, args["before_action_id"], args["before_sha256"], human_uid=task["human_uid"]
    )
    if before["task_id"] != request.task_id or before["boot_id"] != boot_id:
        raise Denied("Before checkpoint must belong to the current destination task and boot")
    record = state.db.execute(
        "SELECT layout_json FROM checkpoint_layouts WHERE action_id=?", (args["before_action_id"],)
    ).fetchone()
    if record is None:
        raise Denied("Fresh before checkpoint with captured layout required")
    before_layout = layout(json.loads(record[0]))
    if (
        hashlib.sha256(canonical(before_layout).encode()).hexdigest()
        != args["before_layout_sha256"]
    ):
        raise Denied("Approved before layout changed")
    operations = plan(desired, previous, before_layout=before_layout)
    review = operations | dict(
        source_task_id=source["task_id"],
        source_boot_id=source["boot_id"],
        source_commit=source_receipt["commit"],
        source_sha256=source_receipt["sha256"],
        before_commit=before_receipt["commit"],
        before_sha256=before_receipt["sha256"],
        before_layout_sha256=args["before_layout_sha256"],
        source_owned_by_same_human=True,
        source_classification=source["classification"],
        runtime_ceiling_seconds=60,
    )
    return dict(review=review, desired=desired, before=previous, before_layout=before_layout)


class Restorer:
    """One bounded restore job, one staged chunk or directory operation per tick."""

    def __init__(self, runtime, *, clock=None):
        import time

        self.runtime = runtime
        self.clock = clock or time.monotonic
        self.jobs = {}

    def authority(self, action_id, expected):
        state = self.runtime.state
        row = state.db.execute(
            "SELECT a.*,g.revoked,g.epoch,g.expires,g.budget_json,"
            "g.approved_args_json,t.boot_id,t.caller_uid,t.human_uid FROM actions a "
            "JOIN grants g ON a.grant_id=g.id JOIN tasks t ON a.task_id=t.id WHERE a.id=?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise Denied("Unknown source restore")
        request = ActionRequest.parse(row["request_json"].encode())
        if (
            row["state"] != expected
            or request.capability != Capability.RESTORE
            or row["revoked"]
            or state.meta("latched")
            or state.meta("epoch") != row["epoch"]
            or row["boot_id"] != self.runtime.boot_id
            or self.clock() >= row["expires"]
            or request.args_json != row["approved_args_json"]
        ):
            raise Denied("Source restore authority expired or revoked")
        return row, request

    def observe(self, job):
        self.runtime.sync_stop()
        self.authority(job["action_id"], "executing")
        if self.clock() >= job["deadline"]:
            raise Denied("Restore runtime ceiling exhausted")

    def current(self, job):
        from .checkpoints import capture

        observed_layout = {}
        data, receipt = capture(
            job["workspace"], observe=lambda: self.observe(job), layout=observed_layout
        )
        args = job["args"]
        if (
            receipt["sha256"] != args["before_sha256"]
            or hashlib.sha256(canonical(observed_layout).encode()).hexdigest()
            != args["before_layout_sha256"]
        ):
            raise Denied("Workspace changed after the approved before checkpoint")
        return data

    def launch(self, action_id):
        import os
        import secrets
        import stat

        from .file_writes import STAGING

        state, registry = self.runtime.state, self.runtime.registry
        import threading

        if self.jobs or threading.active_count() != 1:
            raise Denied("One restore and a single-threaded broker required")
        row, request = self.authority(action_id, "intent")
        prepared = registry.leases.get(action_id)
        resource = registry.resources.get(request.resource_id)
        if (
            prepared is None
            or prepared.closed
            or prepared.started
            or resource is None
            or set(prepared.descriptors) != {"root"}
            or resource.task_id != request.task_id
            or (resource.caller_uid, resource.human_uid, resource.boot_id)
            != (row["caller_uid"], row["human_uid"], self.runtime.boot_id)
            or prepared.resource_id != request.resource_id
        ):
            raise Denied("Exact destination workspace lease required")
        root = prepared.descriptors["root"]
        if root.fd < 0 or (root.device, root.inode) != (
            resource.workspace.device,
            resource.workspace.inode,
        ):
            raise Denied("Restore destination root pin changed")
        if state.db.execute(
            "SELECT count(*) FROM actions WHERE task_id=? AND id!=? "
            "AND state IN ('intent','executing')",
            (request.task_id, action_id),
        ).fetchone()[0]:
            raise Denied("Other destination actions must settle before source restoration")
        if state.db.execute("SELECT count(*) FROM restore_attempts").fetchone()[0] >= 8:
            raise Denied("Restore attempt retention quota exhausted")
        disk = os.statvfs(state.directory)
        if disk.f_bavail * disk.f_frsize < 64 * 1024**2 + 12 * 1024**2:
            raise Denied("Insufficient free space for restore and journal")
        prepared_plan = validate(
            state, request, caller_uid=row["caller_uid"], boot_id=self.runtime.boot_id
        )
        job = dict(
            action_id=action_id,
            args=json.loads(request.args_json),
            workspace=resource.workspace,
            plan=prepared_plan["review"],
            desired=prepared_plan["desired"],
            phase="stage",
            before_layout=prepared_plan["before_layout"],
            pins={},
            stage_parent=-1,
            stage=-1,
            file_fd=-1,
            file_name=None,
            file_offset=0,
            staged={},
            stage_queue=[],
            step=0,
            deadline=self.clock() + min(60, json.loads(row["budget_json"])["max_timeout_seconds"]),
        )
        self.jobs[action_id] = job
        try:
            registry.start(state, action_id, now=self.clock(), boot_id=self.runtime.boot_id)
            self.current(job)
            with state.transaction():
                state.db.execute(
                    "INSERT INTO restore_attempts VALUES(?,?,NULL)",
                    (action_id, canonical(job["plan"])),
                )
            for name in [".", *job["before_layout"]["directories"]]:
                job["pins"][name] = resource.workspace.pin(name, directory=True)
            try:
                os.mkdir(STAGING, mode=0o2700, dir_fd=root.fd)
            except FileExistsError:
                pass
            stage_parent = os.open(
                STAGING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root.fd
            )
            job["stage_parent"] = stage_parent
            info = os.fstat(stage_parent)
            expected = os.fstat(root.fd)
            if (
                info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o777 != 0o700
                or info.st_gid != expected.st_gid
            ):
                raise Denied("Private broker staging required")
            os.mkdir(action_id, mode=0o2700, dir_fd=stage_parent)
            job["stage"] = os.open(
                action_id,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=stage_parent,
            )
            info = os.fstat(job["stage"])
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o777 != 0o700:
                raise Denied("Private restore action directory required")
            for operation in job["plan"]["operations"]:
                if operation["operation"] == "publish":
                    name = operation["path"]
                    job["stage_queue"].append(name)
                    job["staged"][name] = secrets.token_hex(16)
        except BaseException:
            self.fail(action_id)
            raise
        finally:
            registry.release(action_id)

    def poll(self, action_id):
        import os
        from pathlib import PurePosixPath

        from .file_writes import checked
        from .resources import Pinned, library

        job = self.jobs[action_id]
        state = self.runtime.state
        try:
            import threading

            self.observe(job)
            if threading.active_count() != 1:
                raise Denied("Single-threaded fixed-mode creation required")
            native = library()
            if job["phase"] == "stage":
                if job["file_name"] is None and job["stage_queue"]:
                    name = job["stage_queue"].pop(0)
                    job["file_name"], job["file_offset"] = name, 0
                    data, executable = job["desired"][name]
                    job["file_fd"] = checked(
                        native.mano_create_restore_stage(
                            job["stage"], job["staged"][name].encode(), int(executable)
                        )
                    )
                if job["file_name"] is not None:
                    name = job["file_name"]
                    data = job["desired"][name][0]
                    chunk = data[job["file_offset"] : job["file_offset"] + 65536]
                    if chunk:
                        count = os.write(job["file_fd"], chunk)
                        if count <= 0:
                            raise OSError("Incomplete staged restore bytes")
                        job["file_offset"] += count
                    if job["file_offset"] == len(data):
                        os.fsync(job["file_fd"])
                        os.close(job["file_fd"])
                        job["file_fd"] = -1
                        job["file_name"] = None
                    return
                os.fsync(job["stage"])
                self.current(job)  # Recheck after staging, immediately before first public effect.
                job["phase"] = "publish"
                return
            operations = job["plan"]["operations"]
            if job["step"] == len(operations):
                self.finish(job)
                return
            operation = operations[job["step"]]
            name = operation["path"]
            path = PurePosixPath(name)
            parent = job["pins"][str(path.parent)]
            # A retained parent is authority over its original inode. Reject a
            # changed current path before acting; never follow a replacement link.
            with job["workspace"].pin(str(path.parent), directory=True) as current:
                if (current.device, current.inode) != (parent.device, parent.inode):
                    raise Denied("Restore parent path changed")
            with state.transaction():
                self.observe(job)
                state.db.execute(
                    "INSERT INTO restore_steps VALUES(?,?,?,'intent')",
                    (action_id, job["step"], canonical(operation)),
                )
            kind = operation["operation"]
            leaf = path.name.encode()
            if kind == "publish":
                checked(
                    native.mano_publish_restore(
                        job["stage"], job["staged"][name].encode(), parent.fd, leaf
                    )
                )
            elif kind == "mkdir":
                fd = checked(native.mano_restore_mkdir(parent.fd, leaf))
                info = os.fstat(fd)
                job["pins"][name] = Pinned(fd, info.st_dev, info.st_ino)
            elif kind in {"unlink", "rmdir"}:
                checked(native.mano_restore_remove(parent.fd, leaf, int(kind == "rmdir")))
            else:
                raise Denied("Unknown fixed restore operation")
            sync = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent.fd)
            try:
                os.fsync(sync)
            finally:
                os.close(sync)
            with state.transaction():
                self.observe(job)
                state.db.execute(
                    "UPDATE restore_steps SET state='done' WHERE action_id=? AND sequence=?",
                    (action_id, job["step"]),
                )
            job["step"] += 1
        except BaseException:
            self.fail(action_id)
            raise

    def finish(self, job):
        from .checkpoints import capture

        state = self.runtime.state
        observed_layout = {}
        _, receipt = capture(
            job["workspace"], observe=lambda: self.observe(job), layout=observed_layout
        )
        if (
            receipt["sha256"] != job["args"]["source_sha256"]
            or observed_layout["directories"] != job["plan"]["directories"]
            or observed_layout["excluded"] != job["before_layout"]["excluded"]
        ):
            raise Denied(
                "Independent final source bytes/modes/file set did not match saved checkpoint"
            )
        result = dict(
            action_id=job["action_id"],
            source_sha256=job["args"]["source_sha256"],
            before_sha256=job["args"]["before_sha256"],
            files=receipt["files"],
            source_bytes=receipt["source_bytes"],
            commit=receipt["commit"],
            steps=len(job["plan"]["operations"]),
            postcondition_verified=True,
            current_content_verified=False,
            effect_verified=False,
            atomic_filesystem_restore=False,
        )
        with state.transaction():
            self.observe(job)
            state.db.execute(
                "UPDATE restore_attempts SET metadata_json=? WHERE action_id=?",
                (canonical(result), job["action_id"]),
            )
            state.transition(job["action_id"], "done", exit_code=0)
            state.event(job["action_id"], "source-restore-postcondition-captured", result)
        self.close(job["action_id"])

    def fail(self, action_id):
        state = self.runtime.state
        with state.transaction():
            state.db.execute(
                "UPDATE restore_steps SET state='unknown' WHERE action_id=? AND state='intent'",
                (action_id,),
            )
            row = state.db.execute("SELECT state FROM actions WHERE id=?", (action_id,)).fetchone()
            if row and row[0] in {"intent", "executing"}:
                state.transition(action_id, "failed" if row[0] == "intent" else "unknown")
        self.close(action_id)

    def close(self, action_id):
        import contextlib
        import os

        job = self.jobs.pop(action_id, None)
        if job is None:
            return
        incomplete = False
        if job["file_fd"] >= 0:
            with contextlib.suppress(OSError):
                os.close(job["file_fd"])
        if job["stage"] >= 0:
            try:
                for token in job["staged"].values():
                    try:
                        os.unlink(token, dir_fd=job["stage"])
                    except FileNotFoundError:
                        pass
                    except OSError:
                        incomplete = True
            finally:
                os.close(job["stage"])
            try:
                os.rmdir(action_id, dir_fd=job["stage_parent"])
            except FileNotFoundError:
                pass
            except OSError:
                incomplete = True
        if job["stage_parent"] >= 0:
            with contextlib.suppress(OSError):
                os.close(job["stage_parent"])
        for pin in job["pins"].values():
            with contextlib.suppress(OSError):
                pin.close()
        if incomplete:
            self.runtime.state.event(action_id, "restore-private-staging-retained", {})


def result(state, *, task_id, action_id, caller_uid, boot_id):
    from mano_protocol.actions import identifier

    identifier(task_id)
    identifier(action_id)
    row = state.db.execute(
        "SELECT a.*,r.metadata_json,r.plan_json FROM actions a "
        "JOIN tasks t ON a.task_id=t.id LEFT JOIN restore_attempts r ON r.action_id=a.id "
        "WHERE a.id=? AND t.id=? AND t.caller_uid=? AND t.boot_id=?",
        (action_id, task_id, caller_uid, boot_id),
    ).fetchone()
    if (
        row is None
        or ActionRequest.parse(row["request_json"].encode()).capability != Capability.RESTORE
    ):
        raise Denied("Restore attempt unavailable to this task/caller/boot")
    steps = [
        dict(sequence=item["sequence"], state=item["state"])
        for item in state.db.execute(
            "SELECT sequence,state FROM restore_steps WHERE action_id=? ORDER BY sequence",
            (action_id,),
        )
    ]
    receipt = None if row["metadata_json"] is None else json.loads(row["metadata_json"])
    if (row["state"] == "done") != (receipt is not None):
        raise Denied("Restore receipt and journal disagree")
    return dict(
        state=row["state"],
        receipt=receipt,
        steps=steps,
        total_steps=None
        if row["plan_json"] is None
        else len(json.loads(row["plan_json"])["operations"]),
        automatic_retry_authorized=False,
    )
