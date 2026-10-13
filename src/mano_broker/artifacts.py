"""Bounded sealed-byte custody; capture alone never verifies an outcome."""

import fcntl
import hashlib
import os
import secrets
from dataclasses import dataclass

from .protocol import ActionRequest, identifier
from .state import Denied

MAX_BYTES = 8 * 1024**2
MAX_ARTIFACTS = 8


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


@dataclass
class Artifact:
    fd: int
    metadata: dict

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def seal(pin):
    source = pin.read_fd()
    target = -1
    try:
        before = os.fstat(source)
        if not 0 <= before.st_size <= MAX_BYTES:
            raise Denied("Artifact byte quota exceeded")
        target = os.memfd_create("mano-artifact", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        offset = 0
        while True:
            data = os.pread(source, min(65536, MAX_BYTES + 1 - offset), offset)
            if not data:
                break
            offset += len(data)
            if offset > MAX_BYTES:
                raise Denied("Growing artifact exceeded byte quota")
            written = 0
            while written < len(data):
                count = os.write(target, data[written:])
                if count <= 0:
                    raise OSError("Short artifact snapshot write")
                written += count
        after = os.fstat(source)
        if identity(before) != identity(after) or after.st_nlink != 1 or offset != before.st_size:
            raise Denied("Artifact source changed while capturing")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(target, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(target, fcntl.F_GET_SEALS) & seals != seals or os.get_inheritable(target):
            raise Denied("Required immutable artifact seals absent")
        digest = hashlib.sha256()
        for start in range(0, offset, 65536):
            digest.update(os.pread(target, min(65536, offset - start), start))
        result = target
        target = -1
        return result, dict(sha256=digest.hexdigest(), size=offset,
                            source_device=before.st_dev, source_inode=before.st_ino)
    finally:
        os.close(source)
        if target >= 0:
            os.close(target)


class Store:
    def __init__(self):
        self.items = {}
        self.closed = False

    def capture(self, state, registry, action_id, relative, *, boot_id):
        identifier(action_id)
        if self.closed or len(self.items) >= MAX_ARTIFACTS:
            raise Denied("Artifact custody quota exhausted")
        row = state.db.execute(
            "SELECT a.*,t.boot_id,t.human_uid,t.caller_uid FROM actions a "
            "JOIN tasks t ON a.task_id=t.id WHERE a.id=?", (action_id,)
        ).fetchone()
        if row is None or row["state"] != "done" or row["boot_id"] != boot_id:
            raise Denied("Completed current-boot action required")
        request = ActionRequest.parse(row["request_json"].encode())
        resource = registry.resources.get(request.resource_id)
        if (resource is None or resource.task_id != request.task_id
                or (resource.human_uid, resource.caller_uid, resource.boot_id)
                != (row["human_uid"], row["caller_uid"], boot_id)):
            raise Denied("Live completed-action resource custody required")
        with resource.workspace.pin(relative) as pinned:
            fd, metadata = seal(pinned)
        artifact_id = secrets.token_hex(16)
        metadata.update(artifact_id=artifact_id, action_id=action_id,
                        task_id=request.task_id, boot_id=boot_id, effect_verified=False)
        self.items[artifact_id] = Artifact(fd, metadata)
        return dict(metadata)

    def close(self):
        for artifact in self.items.values():
            artifact.close()
        self.items.clear()
        self.closed = True
