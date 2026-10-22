"""Root-terminal recovery driver: disposable Debian guest only, not shipped."""

import fcntl
import hashlib
import json
import os
import subprocess
from pathlib import Path

from ci_tty import native_terminal


def command(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=120)


def terminal(*args, success=True):
    code, output = native_terminal("mano_runtime.recovery", args, source_tree=True)
    assert (code == 0) == success, (code, output[-4096:])
    if success:
        records = [
            json.loads(line) for line in output.decode().splitlines() if line.startswith("{")
        ]
        assert len(records) == 1
        return records[0]
    return output.decode()


def main():
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert command("systemd-detect-virt", "--vm").stdout.strip() in {"kvm", "qemu"}
    # Existing Phase0 script already mounted the fixed top-level disk and configured Snapper.
    assert command("findmnt", "-n", "-o", "FSROOT", "/").stdout.strip() == "/@"
    assert not Path("/usr/games/sl").exists()
    canary = Path("/etc/mano/package-recovery-canary")
    assert not canary.exists()
    canary.write_bytes(b"before package change\x00\xff\n")
    canary.chmod(0o600)
    status = hashlib.sha256(Path("/var/lib/dpkg/status").read_bytes()).hexdigest()
    env = [
        "env",
        "-i",
        "PATH=/usr/bin:/bin",
        "PYTHONPATH=/opt/mano-lab/src",
        "/usr/bin/python3",
        "-P",
        "-m",
        "mano_runtime.recovery",
        "create",
    ]
    assert command(*env, check=False).returncode != 0  # Root without a TTY.
    assert command("runuser", "-u", "mano-agent", "--", *env, check=False).returncode != 0
    # An actual lock held by another process must prevent snapshot creation.
    fd = os.open("/var/lib/dpkg/lock", os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        denied_lock = terminal("create", success=False)
        assert "BlockingIOError" in denied_lock, denied_lock
    finally:
        os.close(fd)
    gap = Path("/var/lib/dpkg/mano-recovery-ci-gap")
    assert not gap.exists()
    command("/usr/bin/btrfs", "subvolume", "create", str(gap))
    try:
        denied_nested = terminal("create", success=False)
        assert "Nested subvolume" in denied_nested, denied_nested
    finally:
        # Delete only the empty subvolume freshly made by this disposable CI test.
        command("/usr/bin/btrfs", "subvolume", "delete", str(gap))
    created = terminal("create")
    assert created["status_sha256"] == status and created["snapshot_read_only"] is True
    assert created["package_install_authorized"] is False
    from mano_runtime import package_attempts
    from mano_runtime import recovery as recovery_runtime

    with recovery_runtime.locked():
        try:
            with recovery_runtime.locked():
                raise AssertionError("Nested package-manager lock scope admitted")
        except BlockingIOError:
            pass
        # Prove the refused nested scope did not release the outer POSIX locks.
        assert "BlockingIOError" in terminal("create", success=False)

    attempt_id = "14" * 16
    # CI context only: this digest is not a broker grant or a human approval.
    request_sha256 = hashlib.sha256(b"controlled CI sl + interrupted dpkg fixture").hexdigest()
    # Only this explicitly guarded CI driver installs the fixed signed Debian test package.
    installed = command("/usr/bin/apt-get", "--no-install-recommends", "-y", "install", "sl")
    assert installed.returncode == 0
    package = command("/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}:${Version}", "sl").stdout
    assert package.startswith("installed:") and Path("/usr/games/sl").is_file()
    changed_status = hashlib.sha256(Path("/var/lib/dpkg/status").read_bytes()).hexdigest()
    assert changed_status != status
    canary.write_bytes(b"after package change\n")
    Path("/etc/mano/recovery-sentinel").write_text("after\n")
    from probe_dpkg_interruption import interrupt_install, journal_inventory

    with recovery_runtime.locked() as scope:
        coherent = recovery_runtime.create_locked()
        intent = package_attempts.begin_locked(attempt_id, request_sha256, coherent["recovery_id"])
        assert intent["state"] == "intent" and intent["installation_authorized"] is False
        try:
            package_attempts.begin_locked(attempt_id, request_sha256, coherent["recovery_id"])
        except FileExistsError:
            pass
        else:
            raise AssertionError("Lost-acknowledgement attempt identity was reused")
        with scope.dpkg_backend() as frontend_env:
            assert frontend_env == {"DPKG_FRONTEND_LOCKED": "1"}
            backend = command(
                "/usr/bin/python3",
                "-I",
                "-c",
                "import fcntl;f=open('/var/lib/dpkg/lock','r+');"
                "fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)",
            )
            assert backend.returncode == 0
            competitor = subprocess.run(
                ["/usr/bin/dpkg", "--configure", "--pending"],
                env=recovery_runtime.ENV,
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert competitor.returncode != 0 and "frontend lock" in competitor.stderr
            for operation in (
                recovery_runtime.create_locked,
                lambda: package_attempts.begin_locked(
                    "15" * 16, request_sha256, coherent["recovery_id"]
                ),
            ):
                try:
                    operation()
                except PermissionError:
                    pass
                else:
                    raise AssertionError("Checkpoint/intent admitted without backend lock")
            interrupted = interrupt_install(
                lambda: terminal("prepare-boot", created["recovery_id"], success=False),
                frontend_scope=scope,
            )
        assert recovery_runtime.require_locked() is scope and scope.backend_held
        coherent_locks = dict(
            checkpoint_and_intent_same_scope=True,
            frontend_retained_backend_temporarily_released=True,
            other_process_backend_lock_succeeded_before_child=True,
            direct_dpkg_frontend_conflict_denied=True,
            checkpoint_and_intent_denied_during_handoff=True,
            backend_reacquired_after_child=True,
            native_dpkg_returncode=interrupted["return_code"],
        )
    journal_entries = interrupted["journal_entries"]
    attempts = package_attempts.reconcile()
    assert len(attempts) == 1 and attempts[0]["intent"] == intent
    assert attempts[0]["outcome"]["state"] == "unknown"
    assert attempts[0]["outcome"]["automatic_replay_allowed"] is False
    assert package_attempts.reconcile() == attempts
    assert "Unsettled dpkg journal" in terminal("create", success=False)
    changed_status = hashlib.sha256(Path("/var/lib/dpkg/status").read_bytes()).hexdigest()
    prepared = terminal("prepare-boot", created["recovery_id"])
    assert prepared["source_package_journal_clean"] is True
    assert prepared["live_package_journal_dirty"] is True
    assert journal_inventory(Path("/var/lib/dpkg/updates"))[0] == journal_entries

    assert prepared["boot_selected"] is prepared["reboot_performed"] is False
    assert prepared["source_root_preserved"] is prepared["source_snapshot_preserved"] is True
    clone = Path("/mnt/mano-root/@recovery")
    assert hashlib.sha256((clone / "var/lib/dpkg/status").read_bytes()).hexdigest() == status
    assert (
        clone / "etc/mano/package-recovery-canary"
    ).read_bytes() == b"before package change\x00\xff\n"
    assert not (clone / "usr/games/sl").exists()
    assert not (clone / "usr/share/mano-recovery-interrupt-ci/payload.bin").exists()
    assert canary.read_bytes() == b"after package change\n"
    assert hashlib.sha256(Path("/var/lib/dpkg/status").read_bytes()).hexdigest() == changed_status
    assert "already exists" in terminal("prepare-boot", created["recovery_id"], success=False)
    witness = dict(
        created=created,
        prepared=prepared,
        source_status_after=changed_status,
        source_package_after=package,
        source_executable_sha256=hashlib.sha256(Path("/usr/games/sl").read_bytes()).hexdigest(),
        root_without_tty_denied=True,
        non_root_denied=True,
        real_dpkg_lock_conflict=True,
        nested_package_subvolume_denied=True,
        duplicate_clone_denied=True,
        current_root_unchanged_by_prepare=True,
        source_tree_cli=True,
        dirty_live_journal_fixture=False,
        actual_dpkg_interruption=True,
        dirty_journal_snapshot_creation_denied=True,
        source_journal_preserved=True,
        interrupted_package=interrupted,
        package_attempts=attempts,
        coherent_checkpoint=coherent,
        coherent_package_locks=coherent_locks,
        duplicate_attempt_denied=True,
        nested_scope_denied_outer_posix_lock_preserved=True,
        repeated_reconciliation_unchanged=True,
        attempt_request_is_ci_context_not_approval=True,
        live_model_connected=False,
        agent_package_install_authorized=False,
    )
    Path("/opt/mano-lab/evidence/package-root-recovery.json").write_text(
        json.dumps(witness, indent=2) + "\n"
    )
    print(created["snapshot_number"])


if __name__ == "__main__":
    main()
