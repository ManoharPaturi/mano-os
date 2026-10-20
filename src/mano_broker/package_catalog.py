"""Root-owned, signed-input package catalog custody. No refresh or execution here."""

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from mano_protocol.actions import canonical, unique_object
from mano_protocol.packages import digest

BASE = Path("/var/lib/mano-packages")
STATUS = Path("/var/lib/dpkg/status")
LISTS = Path("/var/lib/apt/lists")
KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")
UPDATES = Path("/var/lib/dpkg/updates")
MAX_STATUS = 16 * 1024**2
MAX_INPUT = 128 * 1024**2


def trusted(path, *, directory=False):
    for parent in (path, *path.parents):
        info = parent.lstat()
        if (
            info.st_uid != 0
            or stat.S_ISLNK(info.st_mode)
            or info.st_mode & 0o022
            or (parent != path and not stat.S_ISDIR(info.st_mode))
        ):
            raise ValueError("Untrusted package catalog path")
    info = path.lstat()
    if directory != stat.S_ISDIR(info.st_mode):
        raise ValueError("Unexpected package catalog object type")
    if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError("Regular single-link package input required")
    return info


def read(path, maximum):
    trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not 0 <= before.st_size <= maximum:
            raise ValueError("Package catalog input exceeds budget")
        data = bytearray()
        while len(data) <= maximum:
            piece = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
        after = os.fstat(fd)

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError("Package input changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def current_status():
    if any(UPDATES.iterdir()):
        raise ValueError("Unsettled dpkg journal requires operator recovery")
    return hashlib.sha256(read(STATUS, MAX_STATUS)).hexdigest()


def source_identity(path):
    info = trusted(path)
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def load(identifier=None, *, check_current=True):
    active = json.loads(read(BASE / "active.json", 256), object_pairs_hook=unique_object)
    if set(active) != {"catalog_id"}:
        raise ValueError("Invalid active package catalog")
    selected = digest(active["catalog_id"])
    if identifier is not None and digest(identifier) != selected:
        raise ValueError("Package catalog was superseded; request fresh consent")
    root = BASE / "catalogs" / selected
    trusted(root, directory=True)
    value = json.loads(read(root / "manifest.json", 16384), object_pairs_hook=unique_object)
    body = {k: v for k, v in value.items() if k != "catalog_id"}
    if (
        value.get("catalog_id") != selected
        or hashlib.sha256(canonical(body).encode()).hexdigest() != selected
        or value.get("format") != "debian13-amd64-main-v1"
        or type(value.get("created_at")) is not int
        or type(value.get("expires_at")) is not int
        or not value["created_at"] <= time.time() < value["expires_at"]
        or value["expires_at"] - value["created_at"] > 3600
        or value.get("signed_indexes_verified") is not True
        or value.get("architecture") != "amd64"
    ):
        raise ValueError("Invalid or expired package catalog custody")
    digest(value["status_sha256"])
    if check_current and current_status() != value["status_sha256"]:
        raise ValueError("Installed package state changed; refresh catalog and approval")
    if check_current:
        sources = value.get("source_inputs")
        if not isinstance(sources, dict) or not 1 <= len(sources) <= 16:
            raise ValueError("Missing package catalog source identity")
        for name, identity in sources.items():
            if (
                not isinstance(name, str)
                or not re.fullmatch("[A-Za-z0-9_.+-]{1,255}", name)
                or source_identity(LISTS / name) != identity
            ):
                raise ValueError("APT indexes changed; refresh catalog and approval")
        if (
            hashlib.sha256(read(KEYRING, 2 * 1024**2)).hexdigest()
            != value["files"]["inputs/debian-archive-keyring.gpg"]["sha256"]
        ):
            raise ValueError("Debian trust anchors changed; refresh catalog and approval")
    return root, value


def summary():
    _, value = load()
    return {
        key: value[key]
        for key in (
            "catalog_id",
            "created_at",
            "expires_at",
            "architecture",
            "solver",
            "status_sha256",
            "signed_indexes_verified",
            "free_space_bytes",
        )
    }


def validate(request):
    if request.capability == "packages.plan_install":
        return load(json.loads(request.args_json)["catalog_id"])[1]
    return None


def argv(arguments):
    from mano_protocol.packages import arguments as parse

    value = parse(arguments)
    return [
        "/usr/bin/python3",
        "-I",
        "/package-solver.py",
        canonical(value["names"]),
        value["catalog_id"],
    ]
