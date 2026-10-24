"""Explicit Root-terminal Snapper checkpoint and fixed boot-clone preparation.

No public/model endpoint, package manager execution, boot selection, overwrite,
delete, in-place restore or permission-profile grant. Root must configure Snapper.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from mano_broker.package_catalog import MAX_STATUS, UPDATES, current_status, read, trusted
from mano_protocol.actions import canonical, unique_object

STORAGE = Path("/.snapshots")
BASE = STORAGE / ".mano-package-recovery"
TOP = Path("/run/mano-package-recovery-top")
CONFIG = Path("/etc/snapper/configs/mano-root")
CRITICAL = ("/usr", "/etc", "/var/lib/dpkg", "/var/lib/apt", "/var/cache/apt", "/boot")
ENV = {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"}
_PACKAGE_LOCK_SCOPE = threading.Lock()
_ACTIVE_PACKAGE_SCOPE = None


def command(*args):
    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        env=ENV,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    if len(result.stdout.encode()) > 262144 or len(result.stderr.encode()) > 16384:
        raise ValueError("Recovery observation exceeds budget")
    return result.stdout.strip()


def root_guard():
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Explicit Debian Root-terminal administration required")
    if platform.freedesktop_os_release().get("ID") != "debian":
        raise ValueError("Debian recovery policy required")
    if platform.freedesktop_os_release().get("VERSION_ID") != "13":
        raise ValueError("Debian13 recovery policy required")


def guard():
    root_guard()
    if any(not os.isatty(fd) for fd in (0, 1, 2)) or os.fstat(0).st_uid != 0:
        raise PermissionError("Trusted Root controlling terminal required")
    if os.tcgetpgrp(0) != os.getpgrp():
        raise PermissionError("Root terminal must belong to the foreground process group")


def overlaps(left, right):
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


class PackageLocks:
    """One process/thread's lock ownership; not a capability or approval token."""

    def __init__(self, backend_fd):
        self.backend_fd = backend_fd
        self.owner = (os.getpid(), threading.get_ident())
        self.active = True
        self.backend_held = True

    def check(self, *, backend=True):
        root_guard()
        if (
            not self.active
            or _ACTIVE_PACKAGE_SCOPE is not self
            or self.owner != (os.getpid(), threading.get_ident())
            or (backend and not self.backend_held)
        ):
            raise PermissionError("Current owned package-manager lock scope required")

    @contextlib.contextmanager
    def dpkg_backend(self):
        """Keep frontend/APT locks, release only backend for a dpkg child.

        Debian's frontend protocol requires the fixed environment marker yielded
        here. Callers must wait for the child before exiting; failure to reacquire
        the backend is an error, never permission to continue mutation.
        """
        self.check()
        fcntl.lockf(self.backend_fd, fcntl.LOCK_UN)
        self.backend_held = False
        try:
            yield {"DPKG_FRONTEND_LOCKED": "1"}
        finally:
            self.check(backend=False)
            fcntl.lockf(self.backend_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.backend_held = True


def require_locked():
    root_guard()
    if _ACTIVE_PACKAGE_SCOPE is None:
        raise PermissionError("Current owned package-manager lock scope required")
    _ACTIVE_PACKAGE_SCOPE.check()
    return _ACTIVE_PACKAGE_SCOPE


def layout():
    mounts = json.loads(
        command("/usr/bin/findmnt", "--json", "--list", "-o", "TARGET,FSTYPE,FSROOT,UUID,OPTIONS")
    )["filesystems"]
    roots = [row for row in mounts if row["target"] == "/"]
    if len(roots) != 1:
        raise ValueError("One root mount required")
    root = roots[0]
    if (
        root["fstype"] != "btrfs"
        or not re.fullmatch("/[A-Za-z0-9@_.+-]{1,96}", root["fsroot"])
        or "rw" not in root["options"].split(",")
    ):
        raise ValueError("Writable named single-root btrfs subvolume required")
    root_uuid = str(uuid.UUID(root["uuid"]))
    if root_uuid != root["uuid"]:
        raise ValueError("Canonical root filesystem UUID required")
    for row in mounts:
        if row["target"] != "/" and any(overlaps(row["target"], path) for path in CRITICAL):
            raise ValueError("Package state or boot files cross a mount boundary")
    storage = [row for row in mounts if row["target"] == str(STORAGE)]
    if (
        len(storage) != 1
        or storage[0]["fstype"] != "btrfs"
        or storage[0]["uuid"] != root_uuid
        or storage[0]["fsroot"] == root["fsroot"]
    ):
        raise ValueError("Separate persistent Snapper storage on root filesystem required")
    rootid = command("/usr/bin/btrfs", "inspect-internal", "rootid", "/")
    if not re.fullmatch("[1-9][0-9]{0,19}", rootid):
        raise ValueError("Unexpected root subvolume identity")
    for path in CRITICAL:
        trusted(Path(path), directory=True)
        if command("/usr/bin/btrfs", "inspect-internal", "rootid", path) != rootid:
            raise ValueError("Package-state directory is a different subvolume")
    prefix = root["fsroot"].lstrip("/") + "/"
    for line in command("/usr/bin/btrfs", "subvolume", "list", "-o", "/").splitlines():
        match = re.fullmatch(r"ID [0-9]+ gen [0-9]+ top level [0-9]+ path (.+)", line)
        if not match:
            raise ValueError("Ambiguous nested subvolume inventory")
        path = match[1]
        if not path.startswith(prefix):
            raise ValueError("Unexpected nested subvolume namespace")
        relative = "/" + path[len(prefix) :]
        if any(overlaps(relative, critical) for critical in CRITICAL):
            raise ValueError("Nested subvolume would omit package-state files")
    trusted(STORAGE, directory=True)
    if stat.S_IMODE(STORAGE.stat().st_mode) != 0o700:
        raise ValueError("Snapper root snapshots must be private to Root")
    config = read(CONFIG, 16384).decode()
    subvolumes = re.findall(r'^SUBVOLUME="([^"]*)"$', config, re.MULTILINE)
    if subvolumes != ["/"]:
        raise ValueError("Fixed mano-root Snapper config must target root")
    free = os.statvfs(STORAGE)
    available = free.f_bavail * free.f_frsize
    if available < 1024**3:
        raise ValueError("Recovery needs at least 1GiB free; peak change space is not established")
    return dict(
        root_uuid=root_uuid,
        source_fsroot=root["fsroot"],
        root_id=int(rootid),
        storage_fsroot=storage[0]["fsroot"],
        free_bytes=available,
        package_paths=list(CRITICAL),
    )


@contextlib.contextmanager
def locked():
    global _ACTIVE_PACKAGE_SCOPE
    # POSIX record locks belong to the process: closing a second descriptor can
    # drop a lock still needed by an outer scope. Reject nesting/parallel scopes
    # before opening any package-manager descriptor.
    if not _PACKAGE_LOCK_SCOPE.acquire(blocking=False):
        raise BlockingIOError("Package-manager lock scope is already active")
    try:
        with _locked_descriptors() as scope:
            _ACTIVE_PACKAGE_SCOPE = scope
            try:
                yield scope
            finally:
                _ACTIVE_PACKAGE_SCOPE = None
    finally:
        _PACKAGE_LOCK_SCOPE.release()


@contextlib.contextmanager
def _locked_descriptors():
    trusted(STORAGE, directory=True)
    try:
        BASE.mkdir(mode=0o700)
    except FileExistsError:
        pass
    trusted(BASE, directory=True)
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("Private Root recovery custody required")
    descriptors = []
    try:
        for path in (
            BASE / "lock",
            Path("/var/lib/dpkg/lock-frontend"),
            Path("/var/lib/dpkg/lock"),
            Path("/var/lib/apt/lists/lock"),
            Path("/var/cache/apt/archives/lock"),
        ):
            trusted(path.parent, directory=True)
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            descriptors.append(fd)
            info = os.fstat(fd)
            if (
                info.st_uid != 0
                or info.st_nlink != 1
                or not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o022
            ):
                raise ValueError("Untrusted recovery/package-manager lock")
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        scope = PackageLocks(descriptors[2])
        try:
            yield scope
        finally:
            scope.active = False
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def subvolume(path):
    fields = {}
    for line in command("/usr/bin/btrfs", "subvolume", "show", str(path)).splitlines()[1:]:
        if ":" in line:
            key, value = line.strip().split(":", 1)
            if key in {"UUID", "Parent UUID", "Subvolume ID"}:
                if key in fields:
                    raise ValueError("Ambiguous subvolume metadata")
                fields[key] = value.strip()
    return dict(
        uuid=str(uuid.UUID(fields["UUID"])),
        parent_uuid=fields["Parent UUID"],
        subvolume_id=int(fields["Subvolume ID"]),
    )


def save(path, value):
    packet = (canonical(value) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(packet)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create():
    guard()
    layout()  # Unsupported filesystems must fail before touching recovery locks.
    with locked():
        return create_locked()


def create_locked():
    """Checkpoint inside an already-owned coherent scope; never new authority."""
    require_locked()
    before = layout()
    if (
        len(list(BASE.glob("*.json"))) >= 4
        or sum(path.name.isdecimal() for path in STORAGE.iterdir()) >= 16
    ):
        raise ValueError("Recovery retention exhausted; explicit operator review required")
    status = current_status()
    source_info = subvolume(Path("/"))
    number = command(
        "/usr/bin/snapper",
        "--no-dbus",
        "-c",
        "mano-root",
        "create",
        "--type",
        "single",
        "--read-only",
        "--print-number",
        "--description",
        "mano before package change",
    )
    if not re.fullmatch("[1-9][0-9]{0,9}", number):
        raise ValueError("Unexpected Snapper snapshot identity; inspect operator state")
    snapshot = STORAGE / number / "snapshot"
    info = subvolume(snapshot)
    if (
        info["parent_uuid"] != source_info["uuid"]
        or command("/usr/bin/btrfs", "property", "get", str(snapshot), "ro") != "ro=true"
        or hashlib.sha256(read(snapshot / "var/lib/dpkg/status", MAX_STATUS)).hexdigest() != status
        or current_status() != status
    ):
        raise ValueError("Snapshot package state differs; preserve snapshot for inspection")
    after = layout()
    if any(before[key] != after[key] for key in before if key != "free_bytes"):
        raise ValueError("Root layout changed; preserve snapshot for inspection")
    value = dict(
        schema_version="1.0",
        recovery_id=uuid.uuid4().hex,
        snapshot_number=int(number),
        snapshot=info,
        layout=before,
        status_sha256=status,
        created_at=int(time.time()),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        snapshot_read_only=True,
        package_install_authorized=False,
        external_effects_reversible=False,
        peak_change_space_bytes=None,
    )
    save(BASE / (value["recovery_id"] + ".json"), value)
    return value


def recovery_record(identifier):
    if not re.fullmatch("[a-f0-9]{32}", identifier):
        raise ValueError("Exact recovery ID required")
    path = BASE / (identifier + '.json')
    if not path.exists() and not path.is_symlink():
        path = BASE / 'retired' / path.name
    value = json.loads(read(path, 16384), object_pairs_hook=unique_object)
    if (
        value["recovery_id"] != identifier
        or value["snapshot_read_only"] is not True
        or type(value["snapshot_number"]) is not int
        or not 1 <= value["snapshot_number"] <= 9999999999
    ):
        raise ValueError("Invalid recovery custody")
    return value


def recovery_fstab(original, root_uuid, source_fsroot):
    lines, roots = [], 0
    for line in original.splitlines():
        fields = line.split()
        if len(fields) >= 4 and not line.lstrip().startswith("#") and fields[1] == "/":
            roots += 1
            expected = "subvol=" + source_fsroot.lstrip("/")
            options = fields[3].split(",")
            if (
                fields[0] != "UUID=" + root_uuid
                or fields[2] != "btrfs"
                or options.count(expected) != 1
                or sum(option.startswith("subvol=") for option in options) != 1
                or any(option.startswith("subvolid=") for option in options)
            ):
                raise ValueError("Unsupported root fstab; explicit operator review required")
            fields[3] = ",".join("subvol=@recovery" if opt == expected else opt for opt in options)
            line = "\t".join(fields)
        lines.append(line)
    if roots != 1:
        raise ValueError("Exactly one root fstab record required")
    return "\n".join(lines) + "\n"


def recovery_journal_state(source):
    # A pre-existing clean read-only snapshot is the recovery authority. The live
    # journal may be damaged by the failed change; never repair/delete/parse it.
    saved = source / "var/lib/dpkg/updates"
    trusted(saved, directory=True)
    if any(saved.iterdir()):
        raise ValueError("Recovery snapshot contains unsettled package journal")
    trusted(UPDATES, directory=True)
    return dict(
        source_package_journal_clean=True, live_package_journal_dirty=any(UPDATES.iterdir())
    )


def prepare(identifier):
    guard()
    current = layout()
    with locked():
        value = recovery_record(identifier)
        if current["root_uuid"] != value["layout"]["root_uuid"]:
            raise ValueError("Snapshot belongs to another filesystem")
        source = STORAGE / str(value["snapshot_number"]) / "snapshot"
        if subvolume(source) != value["snapshot"]:
            raise ValueError("Snapshot identity changed")
        if command("/usr/bin/btrfs", "property", "get", str(source), "ro") != "ro=true":
            raise ValueError("Recovery source must remain read-only")
        if (
            hashlib.sha256(read(source / "var/lib/dpkg/status", MAX_STATUS)).hexdigest()
            != value["status_sha256"]
        ):
            raise ValueError("Recovery package database differs")
        prepared_fstab = recovery_fstab(
            read(source / "etc/fstab", 16384).decode(),
            current["root_uuid"],
            value["layout"]["source_fsroot"],
        )
        journals = recovery_journal_state(source)  # Package-manager locks remain held.
        try:
            TOP.mkdir(mode=0o700)
        except FileExistsError:
            pass
        trusted(TOP, directory=True)
        if os.path.ismount(TOP) or stat.S_IMODE(TOP.stat().st_mode) != 0o700 or any(TOP.iterdir()):
            raise ValueError("Fixed private recovery mountpoint is occupied")
        command(
            "/usr/bin/mount",
            "-t",
            "btrfs",
            "-o",
            "subvolid=5",
            "UUID=" + current["root_uuid"],
            str(TOP),
        )
        try:
            destination = TOP / "@recovery"
            if destination.exists() or destination.is_symlink():
                raise ValueError(
                    "Recovery target already exists; no overwrite or automatic deletion"
                )
            command("/usr/bin/btrfs", "subvolume", "snapshot", str(source), str(destination))
            # Modify only the fresh clone, never the current root or read-only source.
            fstab = destination / "etc/fstab"
            read(fstab, 16384)  # Recheck trusted regular clone before opening it for write.
            fd = os.open(fstab, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "w") as stream:
                stream.write(prepared_fstab)
                stream.flush()
                os.fsync(stream.fileno())
            clone = subvolume(destination)
            if clone["parent_uuid"] != value["snapshot"]["uuid"]:
                raise ValueError("Fresh clone provenance differs")
            command("/usr/bin/btrfs", "filesystem", "sync", str(TOP))
            result = dict(
                schema_version="1.0",
                recovery_id=identifier,
                root_uuid=current["root_uuid"],
                recovery_fsroot="/@recovery",
                clone=clone,
                status_sha256=value["status_sha256"],
                source_snapshot_preserved=True,
                source_root_preserved=True,
                boot_selected=False,
                reboot_performed=False,
                package_install_authorized=False,
                **journals,
            )
            save(BASE / (identifier + ".prepared.json"), result)
            return result
        finally:
            command("/usr/bin/umount", str(TOP))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("create")
    prepare_parser = sub.add_parser("prepare-boot")
    prepare_parser.add_argument("recovery_id")
    acknowledge_parser = sub.add_parser('acknowledge-attempt')
    acknowledge_parser.add_argument('attempt_id')
    acknowledge_parser.add_argument('recovery_id')
    retire_parser = sub.add_parser('retire-checkpoint')
    retire_parser.add_argument('recovery_id')
    args = parser.parse_args()
    try:
        if args.operation == 'acknowledge-attempt':
            from mano_runtime.package_operator import acknowledge

            value = acknowledge(args.attempt_id, args.recovery_id)
        elif args.operation == 'retire-checkpoint':
            from mano_runtime.package_operator import retire

            value = retire(args.recovery_id)
        else:
            value = create() if args.operation == "create" else prepare(args.recovery_id)
    except subprocess.CalledProcessError as error:
        # Fixed tools report bounded diagnostics to the explicit Root terminal;
        # never exposed through a task/model endpoint or privileged service log.
        print((error.stderr or "")[:4096], file=sys.stderr)
        raise
    print(canonical(value))


if __name__ == "__main__":
    main()
