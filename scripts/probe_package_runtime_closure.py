"""CI-only mapped-file inventory; not proof of complete trusted runtime closure."""

import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

MAX_FILE = 64 * 1024**2
MAX_TOTAL = 256 * 1024**2


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify_mapping(named, descriptor, mapping_inode):
    # /proc/maps uses inode->i_sb->s_dev; Btrfs stat() uses root->anon_dev.
    # The kernel map_files handle identifies the actual mapped object. Compare
    # its fstat to the named file, not the two different device-number interfaces.
    if identity(named) != identity(descriptor) or descriptor.st_ino != mapping_inode:
        raise ValueError("Mapped object and named runtime file differ")


def range_name(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{1,16}-[0-9a-f]{1,16}", value):
        raise ValueError("Bounded kernel mapping range required")
    start, end = (int(part, 16) for part in value.split("-"))
    if start >= end:
        raise ValueError("Increasing kernel mapping range required")
    # maps pads addresses, but map_files rejects leading zeroes in its names.
    return f"{start:x}-{end:x}"


def collect(*, include_init=False, observer=False):
    assert sys.platform == "linux" and os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
        "qemu",
        "kvm",
    }
    records = {}
    identities = {}
    total = 0
    processes = [("observer" if observer else "controller", os.getpid())]
    if include_init:
        processes.append(("init", 1))
    for role, pid in processes:
        # Never read process memory, environment, command input or credentials.
        rows = Path("/proc", str(pid), "maps").read_text().splitlines()
        assert len(rows) <= 4096
        for line in rows:
            columns = line.split(maxsplit=5)
            if len(columns) != 6:
                continue
            name = columns[5]
            if not name.startswith(("/usr/", "/lib/", "/lib64/")):
                continue
            assert not name.endswith(" (deleted)")
            path = Path(name)
            before = path.stat()
            assert stat.S_ISREG(before.st_mode) and before.st_uid == 0
            assert not before.st_mode & 0o022 and 0 < before.st_size <= MAX_FILE
            major, minor = map(lambda v: int(v, 16), columns[3].split(":"))
            digest = hashlib.sha256()
            mapped_file = Path("/proc", str(pid), "map_files", range_name(columns[0]))
            with mapped_file.open("rb") as stream:
                verify_mapping(before, os.fstat(stream.fileno()), int(columns[4]))
                if name in records:
                    assert identity(before) == identities[name]
                    if role not in records[name]["roles"]:
                        records[name]["roles"].append(role)
                    continue
                assert len(records) < 256
                total += before.st_size
                assert total <= MAX_TOTAL
                read = 0
                while piece := stream.read(65536):
                    read += len(piece)
                    assert read <= before.st_size
                    digest.update(piece)
                assert read == before.st_size
                assert identity(os.fstat(stream.fileno())) == identity(before)
            assert identity(path.stat()) == identity(before)
            identities[name] = identity(before)
            records[name] = dict(
                path=name,
                resolved_path=str(path.resolve(strict=True)),
                roles=[role],
                sha256=digest.hexdigest(),
                bytes=before.st_size,
                uid=before.st_uid,
                mode=stat.S_IMODE(before.st_mode),
                device=before.st_dev,
                inode=before.st_ino,
                maps_device=os.makedev(major, minor),
                mapped_object_verified=True,
            )
    assert records
    for role, _pid in processes:
        assert any(role in row["roles"] for row in records.values())
    return dict(
        scope="mapped system files of selected CI processes only",
        records=[records[name] for name in sorted(records)],
        total_bytes=total,
        process_memory_read=False,
        credentials_read=False,
        all_future_subprocess_dependencies_verified=False,
        python_import_closure_verified=False,
        loader_search_policy_verified=False,
        write_protection_verified=False,
        complete_trusted_closure_verified=False,
    )
