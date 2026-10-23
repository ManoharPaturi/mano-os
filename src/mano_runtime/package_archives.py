"""Root-only bounded archive custody from the fixed operator-populated APT cache.

No acquisition, install grant or package execution. Archives are copied, hashed,
kernel-sealed and checked against a freshly re-resolved plan before yielding.
"""

import contextlib
import errno
import fcntl
import hashlib
import os
import stat
import subprocess
from pathlib import Path

from mano_broker.package_catalog import load, trusted
from mano_protocol.stop_state import snapshot
from mano_runtime.package_resolution import current_plan

CACHE = Path("/var/cache/apt/archives")
MAX_ENTRIES = 256
MAX_ARCHIVE = 64 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_SCAN = 2 * MAX_TOTAL


def seals():
    return fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def armed(generation):
    state = snapshot()
    if state.latched or state.generation != generation:
        raise PermissionError("Native Stop changed during archive custody")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def metadata(fd, row):
    value = subprocess.run(
        [
            "/usr/bin/dpkg-deb",
            "--show",
            "--showformat=${Package}\n${Version}\n${Architecture}\n",
            "/proc/self/fd/" + str(fd),
        ],
        pass_fds=(fd,),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        cwd="/",
    )
    expected = (row["name"] + "\n" + row["candidate"] + "\n" + row["architecture"] + "\n").encode()
    if value.returncode != 0 or value.stderr or value.stdout != expected:
        raise ValueError("Signed archive package identity differs from resolution")


def copy_sealed(source, size, generation):
    fd = os.memfd_create("mano-package-archive", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        digest = hashlib.sha256()
        total = 0
        while piece := os.read(source, 65536):
            armed(generation)
            total += len(piece)
            if total > size:
                raise ValueError("Package archive grew during custody")
            digest.update(piece)
            remaining = memoryview(piece)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError(errno.EIO, "Incomplete archive copy")
                remaining = remaining[written:]
        if total != size:
            raise ValueError("Package archive size changed during custody")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals())
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals() != seals():
            raise ValueError("All archive immutability seals required")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, digest.hexdigest()
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def verified_archives(plan):
    """Hold fresh resolution/locks and yield sealed FDs for exact cached archives.

    FDs belong to this context and close on every exit. The future executor must
    consume these FDs within the scope; cache names are diagnostic only.
    Missing archives require separately authorized acquisition, never a fallback.
    """
    descriptors = []
    with current_plan(plan) as resolution:
        expected = {
            row["archive_sha256"]: row for row in plan["changes"] if row["operation"] != "remove"
        }
        if len(expected) != sum(row["operation"] != "remove" for row in plan["changes"]):
            raise ValueError("Ambiguous package archive identity")
        if sum(row["download_bytes"] for row in expected.values()) > MAX_TOTAL or any(
            not 0 < row["download_bytes"] <= MAX_ARCHIVE for row in expected.values()
        ):
            raise ValueError("Archive custody exceeds explicit memory/byte budget")
        found = {}
        scanned = 0
        try:
            if expected:
                trusted(CACHE, directory=True)
                cache_fd = os.open(
                    CACHE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                )
                try:
                    entries = []
                    with os.scandir(cache_fd) as inventory:
                        for entry in inventory:
                            entries.append(entry.name)
                            if len(entries) > MAX_ENTRIES:
                                raise ValueError("APT cache inventory exceeds custody budget")
                    sizes = {row["download_bytes"] for row in expected.values()}
                    for name in sorted(entries):
                        armed(resolution["stop_generation"])
                        if not name.endswith(".deb"):
                            continue
                        trusted(CACHE / name)
                        source = os.open(
                            name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                            dir_fd=cache_fd,
                        )
                        sealed = None
                        try:
                            before = os.fstat(source)
                            if (
                                not stat.S_ISREG(before.st_mode)
                                or before.st_uid != 0
                                or before.st_nlink != 1
                                or before.st_mode & 0o022
                            ):
                                raise ValueError("Untrusted cached package archive")
                            if before.st_size not in sizes:
                                continue
                            scanned += before.st_size
                            if scanned > MAX_SCAN:
                                raise ValueError("Archive verification scan exceeds budget")
                            sealed, digest = copy_sealed(
                                source, before.st_size, resolution["stop_generation"]
                            )
                            if identity(before) != identity(os.fstat(source)):
                                raise ValueError("Cached package archive changed during read")
                            if digest not in expected:
                                continue
                            if digest in found:
                                raise ValueError("Duplicate cache archive requires operator review")
                            row = expected[digest]
                            metadata(sealed, row)
                            found[digest] = dict(
                                name=row["name"],
                                version=row["candidate"],
                                architecture=row["architecture"],
                                sha256=digest,
                                bytes=before.st_size,
                                fd=sealed,
                                cache_name=name,
                                kernel_seals=fcntl.fcntl(sealed, fcntl.F_GET_SEALS),
                            )
                            descriptors.append(sealed)
                            sealed = None  # Context owns this FD from here.
                        finally:
                            os.close(source)
                            if sealed is not None:
                                os.close(sealed)
                finally:
                    os.close(cache_fd)
            if set(found) != set(expected):
                raise ValueError(
                    "Exact signed archives unavailable; authorized acquisition required"
                )
            load(plan["catalog_id"])
            armed(resolution["stop_generation"])
            yield dict(
                resolution=resolution,
                archives=sorted(found.values(), key=lambda row: row["name"]),
                sealed_bytes=sum(row["bytes"] for row in found.values()),
                scan_bytes=scanned,
                network_used=False,
                install_authorized=False,
                effect_verified=False,
                peak_install_space_bytes=None,
            )
        finally:
            for fd in descriptors:
                os.close(fd)
