"""Real signed archives and kernel sealing, guarded disposable Root CI only."""

import errno
import hashlib
import os
import subprocess
from pathlib import Path


def run(plan):
    from probe_package_plans import guard

    guard()
    from mano_broker.package_catalog import current_status
    from mano_runtime.package_archives import CACHE, verified_archives

    before = current_status()
    # Explicit CI-only acquisition, not an implementation of product download consent.
    fetched = subprocess.run(
        [
            "/usr/bin/apt-get",
            "--download-only",
            "--no-install-recommends",
            "--no-remove",
            "-y",
            "install",
            *[row["name"] + "=" + row["candidate"] for row in plan["requested"]],
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    assert fetched.returncode == 0, fetched.stderr[-2048:]
    assert current_status() == before
    with verified_archives(plan) as observed:
        assert observed["install_authorized"] is observed["network_used"] is False
        assert observed["sealed_bytes"] == plan["download_bytes"]
        assert observed["archives"]
        picked = min(observed["archives"], key=lambda row: row["bytes"])
        assert picked["bytes"] < 1024**2
        source = CACHE / picked["cache_name"]
        original = source.read_bytes()
        assert hashlib.sha256(original).hexdigest() == picked["sha256"]
        for row in observed["archives"]:
            fd = row["fd"]
            for change in (lambda fd=fd: os.write(fd, b"x"), lambda fd=fd: os.ftruncate(fd, 0)):
                try:
                    change()
                except OSError as error:
                    assert error.errno == errno.EPERM
                else:
                    raise AssertionError("Root modified a kernel-sealed archive")
        try:
            source.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            os.lseek(picked["fd"], 0, os.SEEK_SET)
            assert os.read(picked["fd"], len(original) + 1) == original
        finally:
            source.write_bytes(original)
        fds = [row["fd"] for row in observed["archives"]]
        records = [
            {key: value for key, value in row.items() if key != "fd"}
            for row in observed["archives"]
        ]
        resolution = observed["resolution"]
    for fd in fds:
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("Archive FD survived custody scope")
    count = len(list(Path("/proc/self/fd").iterdir()))
    try:
        source.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        try:
            with verified_archives(plan):
                raise AssertionError("Corrupt cached archive admitted")
        except ValueError as error:
            assert "archives unavailable" in str(error)
    finally:
        source.write_bytes(original)
    symlink = CACHE / "mano-archive-symlink-ci.deb"
    assert not symlink.exists() and not symlink.is_symlink()
    symlink.symlink_to(source)
    try:
        try:
            with verified_archives(plan):
                raise AssertionError("Symlink cache input admitted")
        except ValueError as error:
            assert "Untrusted package catalog path" in str(error)
    finally:
        symlink.unlink()  # Only this freshly created disposable CI symlink.
    private = CACHE / ".mano-archive-missing-ci"
    assert not private.exists() and not private.is_symlink()
    private.mkdir(mode=0o700)
    held = private / "archive.deb"
    source.rename(held)
    try:
        try:
            with verified_archives(plan):
                raise AssertionError("Missing archive caused implicit acquisition")
        except ValueError as error:
            assert "authorized acquisition required" in str(error)
    finally:
        held.rename(source)
        private.rmdir()  # Only the new empty CI fixture directory.
    assert len(list(Path("/proc/self/fd").iterdir())) == count
    assert current_status() == before
    assert hashlib.sha256(source.read_bytes()).hexdigest() == picked["sha256"]
    return dict(
        archives=records,
        resolution=resolution,
        sealed_bytes=sum(row["bytes"] for row in records),
        signed_archive_metadata_matched=True,
        root_write_and_truncate_denied=True,
        cache_mutation_did_not_change_sealed_bytes=True,
        corrupt_cache_denied=True,
        symlink_cache_denied=True,
        missing_cache_denied_no_fetch=True,
        scope_exit_closed_fds=True,
        exception_paths_no_fd_leak=True,
        dpkg_state_unchanged=True,
        ci_only_external_acquisition=True,
        product_network_acquisition_authorized=False,
        install_authorized=False,
        package_apply_invoked=False,
        peak_install_space_bytes=None,
    )
