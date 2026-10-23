"""Standalone fixed solver, mounted alone into an unprivileged read-only sandbox.

No broker import, update/fetch/commit, maintainer execution, host configuration,
network or apply operation. The outer supervisor owns deadline/cgroup/Stop.
"""

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

CATALOG = Path("/usr/lib/mano-os/package-catalog")
STAGE = "admission"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(manifest, *, catalog=None):
    catalog = CATALOG if catalog is None else catalog
    total = 0
    files = manifest["files"]
    if not isinstance(files, dict) or not 5 <= len(files) <= 16:
        raise ValueError("Bounded catalog inputs required")
    for name, expected in files.items():
        if (
            not isinstance(name, str)
            or not name.startswith("inputs/")
            or ".." in name
            or not re.fullmatch("[A-Za-z0-9_./+-]+", name)
        ):
            raise ValueError("Invalid catalog input name")
        path = catalog / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Regular immutable catalog input required")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while piece := stream.read(65536):
                size += len(piece)
                total += len(piece)
                if total > 128 * 1024**2:
                    raise ValueError("Catalog byte budget exceeded")
                digest.update(piece)
        if expected != dict(bytes=size, sha256=digest.hexdigest()):
            raise ValueError("Signed catalog snapshot integrity changed")


def prepare_apt_root(root, *, catalog=None):
    catalog = CATALOG if catalog is None else catalog
    for relative in (
        "etc/apt/trusted.gpg.d",
        "etc/apt/apt.conf.d",
        "etc/apt/preferences.d",
        "var/lib/apt/lists/partial",
        "var/lib/dpkg/updates",
        "var/cache/apt/archives/partial",
        "var/log/apt",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(catalog / "inputs/sources.list", root / "etc/apt/sources.list")
    shutil.copyfile(
        catalog / "inputs/debian-archive-keyring.gpg", root / "etc/apt/trusted.gpg.d/debian.gpg"
    )
    # apt.Cache(rootdir=...) requires a writable lists/partial directory even
    # without update/fetch. Only that scratch directory is private and writable;
    # each actual signed list remains a read-only catalog file.
    for path in (catalog / "inputs/lists").iterdir():
        (root / "var/lib/apt/lists" / path.name).symlink_to(path)
    (root / "var/lib/dpkg/status").symlink_to(catalog / "inputs/status")
    (root / "var/lib/apt/extended_states").symlink_to(catalog / "inputs/extended_states")


def change_operation(package):
    if package.marked_delete:
        return "remove"
    # APT can mark a previously absent package as upgraded. Installed state
    # distinguishes a new install before consulting the dependency-cache flags.
    if package.installed is None:
        return "install"
    if package.marked_downgrade:
        return "downgrade"
    if package.marked_upgrade:
        return "upgrade"
    if package.marked_reinstall:
        return "reinstall"
    raise ValueError("Unsupported package version transition")


def resolve_requests(cache, names):
    for name in names:
        if (
            name not in cache
            or cache[name].candidate is None
            or not cache[name].candidate.downloadable
        ):
            raise ValueError("Requested package has no signed catalog candidate")
        cache[name].mark_install(auto_fix=True, auto_inst=True, from_user=True)
    if cache.broken_count:
        raise ValueError("Requested package dependencies cannot be resolved")
    # Later marks can change earlier candidates. Review only the final cache,
    # and refuse a resolution that removes any explicitly requested package.
    requested = []
    for name in names:
        package = cache[name]
        if (
            package.marked_delete
            or package.candidate is None
            or not package.candidate.downloadable
        ):
            raise ValueError("Final resolution does not retain a requested candidate")
        requested.append(dict(
            name=name,
            installed=package.installed.version if package.installed else None,
            candidate=package.candidate.version,
        ))
    return requested


def solve(names, identifier):
    global STAGE
    if (
        sys.platform != "linux"
        or os.geteuid() == 0
        or not isinstance(names, list)
        or not 1 <= len(names) <= 8
        or names != sorted(set(names))
        or any(
            not isinstance(n, str) or not re.fullmatch("[a-z0-9][a-z0-9+.-]{1,63}", n)
            for n in names
        )
        or not re.fullmatch("[a-f0-9]{64}", identifier)
    ):
        raise ValueError("Exact bounded Debian package request required")
    return _resolve_catalog(names, identifier, catalog=CATALOG)


def _resolve_catalog(names, identifier, *, catalog):
    """Read-only APT calculation shared with the isolated Root verifier.

    The caller owns identity, fixed catalog-path custody and current host checks.
    This never fetches, commits or executes package scripts.
    """
    global STAGE
    STAGE = "catalog"
    manifest = json.loads((catalog / "manifest.json").read_text())
    body = {k: v for k, v in manifest.items() if k != "catalog_id"}
    if (
        manifest["catalog_id"] != identifier
        or hashlib.sha256(canonical(body).encode()).hexdigest() != identifier
        or manifest["format"] != "debian13-amd64-main-v1"
        or manifest["signed_indexes_verified"] is not True
        or not manifest["created_at"] <= time.time() < manifest["expires_at"]
    ):
        raise ValueError("Package catalog identity/freshness changed")
    fingerprint(manifest, catalog=catalog)
    STAGE = "import"
    import apt_pkg

    with tempfile.TemporaryDirectory(prefix="apt-plan-", dir="/tmp") as temporary:
        root = Path(temporary)
        prepare_apt_root(root, catalog=catalog)
        # Importing apt initializes configuration. Point it at the empty private
        # tree first; missing host /etc/apt is neither an input nor a warning.
        apt_pkg.config.set("Dir", str(root))
        apt_pkg.config.set("Dir::Etc", str(root / "etc/apt"))
        apt_pkg.init_config()
        import apt
        import apt.progress.base

        apt_pkg.config.set("APT::Architecture", "amd64")
        apt_pkg.config.set("APT::Architectures::", "amd64")
        apt_pkg.config.set("APT::Install-Recommends", "false")
        apt_pkg.config.set("APT::Install-Suggests", "false")
        STAGE = "cache"
        cache = apt.Cache(progress=apt.progress.base.OpProgress(), rootdir=str(root), memonly=True)
        try:
            if cache.broken_count or cache.dpkg_journal_dirty:
                raise ValueError("Installed package state needs operator recovery")
            STAGE = "resolve"
            value = forecast(cache, names, identifier, manifest)
        finally:
            cache.close()
    STAGE = "recheck"
    fingerprint(manifest, catalog=catalog)
    if time.time() >= manifest["expires_at"]:
        raise ValueError("Catalog expired during package resolution")
    return value



def forecast(cache, names, identifier, manifest):
    """Build the same exact full solution from a marked private APT cache."""
    global STAGE
    requested = resolve_requests(cache, names)
    changed = cache.get_changes()
    if len(changed) > 64:
        raise ValueError("Dependency change set exceeds review budget")
    STAGE = "forecast"
    changes = []
    for package in sorted(changed, key=lambda p: p.name):
        installed, candidate = package.installed, package.candidate
        operation = change_operation(package)
        removal = operation == "remove"
        selected = installed if removal else candidate
        if selected is None:
            raise ValueError("Resolved package lacks exact version accounting")
        sha = None if removal else candidate.record.get("SHA256")
        changes.append(
            dict(
                name=package.name,
                operation=operation,
                installed=installed.version if installed else None,
                candidate=None if removal else candidate.version,
                architecture=selected.architecture,
                archive_sha256=sha,
                download_bytes=0 if removal else candidate.size,
                installed_bytes=selected.installed_size,
            )
        )
    value = dict(
        schema_version="1.0",
        names=names,
        catalog_id=identifier,
        status_sha256=manifest["status_sha256"],
        solver=manifest["solver"],
        requested=requested,
        changes=changes,
        download_bytes=cache.required_download,
        net_installed_bytes=cache.required_space,
        peak_space_bytes=None,
        free_space_bytes_at_catalog=manifest["free_space_bytes"],
        catalog_expires_at=manifest["expires_at"],
        install_authorized=False,
        effect_verified=False,
        host_archive_cache_considered=False,
        network_used=False,
        maintainer_scripts_executed=False,
    )
    return value

def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError("Fixed package solver arguments required")
        value = solve(json.loads(sys.argv[1]), sys.argv[2])
        packet = canonical(value).encode()
        if len(packet) > 49152:
            raise ValueError("Package plan exceeds output budget")
        sys.stdout.buffer.write(packet + b"\n")
    except Exception as error:
        # No source paths, package descriptions, inherited config or raw APT errors.
        print(
            canonical(
                dict(
                    error="package-plan-unavailable",
                    stage=STAGE,
                    error_type=type(error).__name__[:64],
                )
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
