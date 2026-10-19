#!/usr/bin/env python3
"""Hash-pinned optional vendor CLIs in guarded CI guests only; never execute as Root."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path("/usr/lib/mano-delegates")
ARCHIVE_LIMIT = 256 * 1024**2
UNPACK_LIMIT = 768 * 1024**2


def main():
    if (
        os.geteuid() != 0
        or Path("/etc/mano-lab-disposable").read_text().strip() != "mano-phase0-ci"
        or subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip()
        not in {"kvm", "qemu"}
    ):
        raise PermissionError("Disposable Debian guest required")
    if ROOT.exists() or shutil.disk_usage("/usr/lib").free < 2 * UNPACK_LIMIT + 512 * 1024**2:
        raise ValueError("Fresh vendor directory and sufficient guest disk required")
    source = Path("/opt/mano-lab/packaging/delegates/linux-amd64.lock.json")
    lock = json.loads(source.read_text())
    ROOT.mkdir(mode=0o755)
    ROOT.chmod(0o755)
    records = {}
    for name, item in lock["delegates"].items():
        destination = ROOT / (name + "-" + item["version"])
        destination.mkdir(mode=0o755)
        destination.chmod(0o755)
        with tempfile.TemporaryDirectory(prefix="mano-ci-delegate-") as temp:
            archive = Path(temp) / "vendor.tar.gz"
            digest = hashlib.sha512()
            size = 0
            with (
                urllib.request.urlopen(item["url"], timeout=60) as response,
                archive.open("xb") as out,
            ):
                if response.url.split("/", 3)[2] not in {
                    "storage.googleapis.com",
                    "registry.npmjs.org",
                }:
                    raise ValueError("Unexpected vendor download origin")
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > ARCHIVE_LIMIT:
                        raise ValueError("Vendor archive exceeds guest budget")
                    digest.update(chunk)
                    out.write(chunk)
            if digest.hexdigest() != item["sha512"]:
                raise ValueError("Pinned vendor archive digest mismatch")
            total = 0
            with tarfile.open(archive, "r:gz") as bundle:
                for member in bundle:
                    if name == "antigravity":
                        if member.name != item["archive_member"]:
                            continue
                        relative = "agy"
                    else:
                        prefix = item["archive_prefix"]
                        if not member.name.startswith(prefix):
                            continue
                        relative = member.name[len(prefix) :]
                        if not relative or member.isdir():
                            continue
                    path = PurePosixPath(relative)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or str(path) != relative
                        or not member.isfile()
                        or member.size < 0
                    ):
                        raise ValueError("Unsafe vendor archive entry")
                    total += member.size
                    if total > UNPACK_LIMIT:
                        raise ValueError("Vendor payload exceeds guest budget")
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    for parent in (target.parent, *target.parent.parents):
                        if parent == ROOT:
                            break
                        parent.chmod(0o755)
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise ValueError("Missing regular vendor payload")
                    with stream, target.open("xb") as output:
                        shutil.copyfileobj(stream, output, length=1024 * 1024)
                    target.chmod(0o555 if member.mode & 0o111 or name == "antigravity" else 0o444)
            executable = Path(item["executable"])
            info = executable.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or not info.st_mode & 0o111
                or info.st_mode & 0o022
            ):
                raise ValueError("Invalid installed vendor executable")
            with executable.open("rb") as binary:
                binary_digest = hashlib.file_digest(binary, "sha256").hexdigest()
            records[name] = item | dict(
                binary_sha256=binary_digest, archive_bytes=size, installed_bytes=total
            )
    manifest = dict(
        schema_version="1.0",
        delegates=records,
        installed_in_ci=True,
        shipped_in_runtime_package=False,
        authenticated_model_calls=False,
    )
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (ROOT / "manifest.json").chmod(0o444)
    print(
        json.dumps(
            dict(
                installed_versions={k: v["version"] for k, v in records.items()},
                authenticated_model_calls=False,
            )
        )
    )


if __name__ == "__main__":
    main()
