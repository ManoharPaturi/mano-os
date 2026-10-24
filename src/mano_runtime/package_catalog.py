"""Explicit Root-only offline catalog refresh; no download, package install or hooks."""

import contextlib
import email.parser
import email.utils
import fcntl
import hashlib
import json
import os
import platform
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mano_broker.package_catalog import (
    BASE,
    MAX_INPUT,
    MAX_STATUS,
    STATUS,
    current_status,
    extended_identity,
    extended_states,
    read,
    source_identity,
)
from mano_protocol.actions import canonical

LISTS = Path("/var/lib/apt/lists")
KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.pgp")
REPOS = (
    ("trixie", ("deb.debian.org_debian", "_etc_apt_mirrors_debian.list"), "http://deb.debian.org/debian"),
    ("trixie-updates", ("deb.debian.org_debian", "_etc_apt_mirrors_debian.list"), "http://deb.debian.org/debian"),
    (
        "trixie-security",
        ("deb.debian.org_debian-security", "security.debian.org_debian-security",
         "_etc_apt_mirrors_debian-security.list"),
        "http://deb.debian.org/debian-security",
    ),
)
ENV = {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"}
_RESERVED_LOCK = None


def guard():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise PermissionError("Explicit Debian Root catalog administration required")
    release = platform.freedesktop_os_release()
    if (
        release.get("ID") != "debian"
        or release.get("VERSION_ID") != "13"
        or platform.machine() != "x86_64"
    ):
        raise ValueError("Debian13 amd64 package policy required")


def command(*args, **kwargs):
    return subprocess.run(
        args,
        env=ENV,
        stdin=subprocess.DEVNULL,
        check=True,
        stderr=subprocess.PIPE,
        timeout=30,
        **kwargs,
    )


def stamp(value):
    parsed = email.utils.parsedate_to_datetime(value)
    if parsed.utcoffset() is None:
        raise ValueError("Signed repository date requires a timezone")
    return int(parsed.timestamp())


def signed_release(source, target, suite, now):
    packet = read(source, 256 * 1024)
    target.write_bytes(packet)
    target.chmod(0o444)
    plaintext = target.parent / (suite + ".verified-release")
    command(
        "/usr/bin/gpgv",
        "--homedir",
        str(target.parent),
        "--keyring",
        str(KEYRING),
        "--output",
        str(plaintext),
        str(target),
        stdout=subprocess.DEVNULL,
    )
    data = plaintext.read_bytes()
    if len(data) > 256 * 1024:
        raise ValueError("Signed Release exceeds metadata budget")
    fields = email.parser.Parser().parsestr(data.decode("utf8"))
    for field in ('Codename','Origin','Architectures','Components','Date','SHA256'):
        if len(fields.get_all(field,[])) != 1:
            raise ValueError('Ambiguous signed repository metadata')
    if len(fields.get_all('Valid-Until',[])) > 1:
        raise ValueError('Ambiguous signed repository freshness')
    if (
        fields.get("Codename") != suite
        or fields.get("Origin") != "Debian"
        or "amd64" not in fields.get("Architectures", "").split()
        or ("updates/main" if suite == "trixie-security" else "main")
        not in fields.get("Components", "").split()
        or stamp(fields["Date"]) > now + 300
    ):
        raise ValueError("Signed Debian repository identity changed")
    expiry = stamp(fields["Valid-Until"]) if fields.get("Valid-Until") else None
    if expiry is not None and expiry <= now:
        raise ValueError("Signed package catalog has expired; refresh APT as operator")
    if suite != "trixie" and expiry is None:
        raise ValueError("Updates/security catalog needs signed freshness")
    indexes = {}
    for line in fields.get("SHA256", "").splitlines():
        if not line.strip():
            continue
        sha, size, name = line.split()
        if name in indexes:
            raise ValueError("Duplicate signed package index")
        indexes[name] = (sha, int(size))
    expected = indexes["main/binary-amd64/Packages"]
    if not 0 <= expected[1] <= 512 * 1024**2:
        raise ValueError("Package index exceeds decompression budget")
    return (
        dict(
            suite=suite,
            release_sha256=hashlib.sha256(packet).hexdigest(),
            date=stamp(fields["Date"]),
            valid_until=expiry,
        ),
        expected,
        plaintext,
    )


def build():
    with retention_slot():
        return build_locked()


@contextlib.contextmanager
def retention_slot():
    """Reserve one of the unchanged four catalog slots before package effects."""
    global _RESERVED_LOCK
    guard()
    if _RESERVED_LOCK is not None:
        raise PermissionError('Catalog reservation cannot be nested')
    # Fixed paths only; never caller-supplied mirrors, shell commands or destinations.
    for directory in (BASE, BASE / "catalogs"):
        created = False
        try:
            directory.mkdir(mode=0o755)
            created = True
        except FileExistsError:
            pass
        from mano_broker.package_catalog import trusted

        trusted(directory, directory=True)
        if created:
            directory.chmod(0o755)
        elif directory.stat().st_mode & 0o7777 != 0o755:
            raise ValueError("Existing catalog directory has unexpected privacy policy")
    lock = os.open(
        BASE / "refresh.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        info = os.fstat(lock)
        if (
            info.st_uid != 0
            or info.st_nlink != 1
            or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("Unexpected package catalog lock custody")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if len(list((BASE / 'catalogs').iterdir())) >= 4:
            raise ValueError('Catalog retention exhausted; explicit operator retention required')
        _RESERVED_LOCK = lock
        try:
            yield
        finally:
            _RESERVED_LOCK = None
    finally:
        os.close(lock)


def repository_prefix(suite, prefixes):
    candidates = [
        prefix for prefix in prefixes
        if (LISTS / (prefix + "_dists_" + suite + "_InRelease")).is_file()
    ]
    if len(candidates) != 1:
        raise ValueError("Exactly one official Debian catalog per suite is required")
    return candidates[0] + "_dists_" + suite


def build_locked():
    if _RESERVED_LOCK is None:
        raise PermissionError('Owned catalog retention reservation required')
    if len(list((BASE / "catalogs").iterdir())) >= 4:
        raise ValueError("Catalog retention exhausted; explicit operator retention required")
    disk = os.statvfs(BASE)
    if disk.f_bavail * disk.f_frsize < 1024**3:
        raise ValueError("At least 1GiB free is required for bounded catalog staging")
    now = int(time.time())
    status = read(STATUS, MAX_STATUS)
    original_status = hashlib.sha256(status).hexdigest()
    original_extended = extended_states()
    with tempfile.TemporaryDirectory(prefix=".catalog-", dir=BASE) as temporary:
        stage = Path(temporary)
        inputs = stage / "inputs"
        (inputs / "lists").mkdir(parents=True)
        (inputs / "status").write_bytes(status)
        (inputs / "extended_states").write_bytes(original_extended or b"")
        (inputs / "debian-archive-keyring.gpg").write_bytes(read(KEYRING, 2 * 1024**2))
        repos, sources = [], []
        source_inputs = {}
        for suite, prefixes, uri in REPOS:
            prefix = repository_prefix(suite, prefixes)
            release_name = prefix + "_InRelease"
            # Cloud images use fixed mirror+file URI identities. Normalize only
            # snapshot filenames to the fixed official source URI used by APT.
            canonical_prefix = prefixes[0] + "_dists_" + suite
            canonical_release = canonical_prefix + "_InRelease"
            source_inputs[release_name] = source_identity(LISTS / release_name)
            repo, expected, plaintext = signed_release(
                LISTS / release_name, inputs / "lists" / canonical_release, suite, now
            )
            index_prefix = prefix + "_main_binary-amd64_Packages"
            candidates = [
                LISTS / (index_prefix + suffix)
                for suffix in (".lz4", ".gz", ".xz", "")
                if (LISTS / (index_prefix + suffix)).is_file()
            ]
            if len(candidates) != 1:
                raise ValueError("Exactly one signed package index is required")
            selected = candidates[0]
            source_inputs[selected.name] = source_identity(selected)
            compressed = read(selected, MAX_INPUT)
            canonical_index = (
                canonical_prefix + "_main_binary-amd64_Packages" + selected.name[len(index_prefix):]
            )
            snapshot = inputs / "lists" / canonical_index
            snapshot.write_bytes(compressed)
            decompressed = stage / (suite + ".packages")

            def cap_file():
                resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024**2, 512 * 1024**2))

            with decompressed.open("wb") as stream:
                command(
                    "/usr/lib/apt/apt-helper",
                    "cat-file",
                    str(snapshot),
                    stdout=stream,
                    preexec_fn=cap_file,
                )
            digest = hashlib.sha256()
            with decompressed.open("rb") as stream:
                while piece := stream.read(65536):
                    digest.update(piece)
            if (digest.hexdigest(), decompressed.stat().st_size) != expected:
                raise ValueError("APT package bytes differ from signed Release SHA256")
            repo.update(packages_sha256=expected[0],packages_bytes=expected[1],
                        signature_verified=True,index_file=canonical_index,
                        index_sha256=hashlib.sha256(compressed).hexdigest())
            decompressed.unlink()  # Only this fresh helper-owned temporary file.
            plaintext.unlink()
            repos.append(repo)
            sources.append("deb [arch=amd64] " + uri + " " + suite + " main\n")
        (inputs / "sources.list").write_text("".join(sources))
        if current_status() != original_status:
            raise ValueError("Installed package state changed while creating catalog")
        if any(
            source_identity(LISTS / name) != identity for name, identity in source_inputs.items()
        ):
            raise ValueError("APT indexes changed while creating catalog")
        if extended_states() != original_extended:
            raise ValueError("APT package marks changed while creating catalog")
        files, total = {}, 0
        for path in sorted(inputs.rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            total += len(data)
            if total > MAX_INPUT:
                raise ValueError("Catalog aggregate bytes exceed budget")
            files[str(path.relative_to(stage))] = dict(
                bytes=len(data), sha256=hashlib.sha256(data).hexdigest()
            )
            path.chmod(0o444)
        solver = (
            command(
                "/usr/bin/dpkg-query", "-W", "-f=${Version}", "python3-apt", stdout=subprocess.PIPE
            )
            .stdout.decode()
            .strip()
        )
        body = dict(
            format="debian13-amd64-main-v1",
            created_at=now,
            expires_at=min([now + 3600] + [r["valid_until"] for r in repos if r["valid_until"]]),
            architecture="amd64",
            solver="python3-apt/" + solver,
            status_sha256=original_status,
            signed_indexes_verified=True,
            free_space_bytes=disk.f_bavail * disk.f_frsize,
            repositories=repos,
            files=files,
            source_inputs=source_inputs,
            extended_states_source=extended_identity(original_extended),
        )
        identifier = hashlib.sha256(canonical(body).encode()).hexdigest()
        value = body | dict(catalog_id=identifier)
        (stage / "manifest.json").write_text(canonical(value) + "\n")
        (stage / "manifest.json").chmod(0o444)
        for directory in sorted(inputs.rglob("*"), reverse=True):
            if directory.is_dir():
                directory.chmod(0o555)
        inputs.chmod(0o555)
        published = BASE / "catalogs" / identifier
        # No existing version is overwritten; immutable inputs remain for in-flight plans.
        if published.exists():
            raise ValueError("Catalog ID already retained")
        shutil.copytree(stage, published)
        published.chmod(0o555)
        for path in published.rglob("*"):
            if path.is_file():
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        for path in (
            published / "inputs/lists",
            published / "inputs",
            published,
            BASE / "catalogs",
        ):
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        active = BASE / (".active-" + identifier)
        fd = os.open(active, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(canonical(dict(catalog_id=identifier)) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(active, BASE / "active.json")
        directory = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {key: value[key] for key in ("catalog_id", "created_at", "expires_at", "solver")}


def main():
    if len(sys.argv) != 1:
        raise ValueError("Catalog refresh has no caller-selected arguments")
    print(json.dumps(build(), sort_keys=True))


if __name__ == "__main__":
    main()
