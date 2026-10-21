#!/usr/bin/env python3
"""Read actual boot/filesystem state, including the preserved changed source root."""

import json
import os
import platform
import subprocess
from pathlib import Path


def main():
    if platform.system() != "Linux" or os.getuid() != 0:
        raise RuntimeError("Disposable Linux guest root context required")
    marker = Path("/etc/mano-lab-disposable")
    if not marker.is_file() or marker.read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("CI guest marker absent")
    kind = subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip()
    if kind not in {"kvm", "qemu"}:
        raise RuntimeError("Disposable QEMU guest required")
    mount = json.loads(
        subprocess.check_output(
            [
                "findmnt",
                "--json",
                "--target",
                "/",
                "-o",
                "TARGET,SOURCE,FSTYPE,FSROOT,UUID,OPTIONS",
            ],
            text=True,
        )
    )
    root = mount["filesystems"][0]
    assert root["fstype"] == "btrfs" and root["fsroot"] == "/@recovery", root
    restored = Path("/etc/mano/recovery-sentinel").read_text()
    assert restored == "before\n", restored
    subprocess.run(["mkdir", "-p", "/mnt/mano-root"], check=True)
    subprocess.run(["mount", "-o", "subvolid=5", "/dev/vdc", "/mnt/mano-root"], check=True)
    try:
        changed = Path("/mnt/mano-root/@/etc/mano/recovery-sentinel").read_text()
        assert changed == "after\n", changed
        source = json.loads(
            Path("/mnt/mano-root/@/opt/mano-lab/evidence/root-snapshot.json").read_text()
        )
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        assert boot_id != source["source_boot_id"], "Expected a distinct real boot"
        snapshot_mount = json.loads(
            subprocess.check_output(
                [
                    "findmnt",
                    "--json",
                    "--target",
                    "/.snapshots",
                    "-o",
                    "TARGET,FSTYPE,FSROOT",
                ],
                text=True,
            )
        )
        assert snapshot_mount["filesystems"][0]["fsroot"] == "/@snapshots", snapshot_mount
        package_source = json.loads(
            Path("/mnt/mano-root/@/opt/mano-lab/evidence/package-root-recovery.json").read_text()
        )
        import hashlib

        restored_status = hashlib.sha256(Path("/var/lib/dpkg/status").read_bytes()).hexdigest()
        assert restored_status == package_source["created"]["status_sha256"]
        assert not Path("/usr/games/sl").exists()
        assert Path("/mnt/mano-root/@/usr/games/sl").is_file()
        assert (
            Path("/etc/mano/package-recovery-canary").read_bytes()
            == b"before package change\x00\xff\n"
        )
        assert (
            Path("/mnt/mano-root/@/etc/mano/package-recovery-canary").read_bytes()
            == b"after package change\n"
        )
        assert (
            hashlib.sha256(Path("/mnt/mano-root/@/var/lib/dpkg/status").read_bytes()).hexdigest()
            == package_source["source_status_after"]
        )
        assert boot_id != package_source["created"]["boot_id"]
        assert not any(Path("/var/lib/dpkg/updates").iterdir())
        from probe_dpkg_interruption import PAYLOAD, PAYLOAD_BYTES, journal_inventory

        assert (
            journal_inventory(Path("/mnt/mano-root/@/var/lib/dpkg/updates"))[0]
            == package_source["interrupted_package"]["journal_entries"]
        )
        assert not PAYLOAD.exists()
        assert (Path("/mnt/mano-root/@") / PAYLOAD.relative_to("/")).read_bytes() == PAYLOAD_BYTES

        package_source["actual_recovery_boot"] = dict(
            boot_id=boot_id,
            restored_status_sha256=restored_status,
            executable_absent=True,
            binary_etc_canary_restored=True,
            changed_source_preserved=True,
            root_fsroot=root["fsroot"],
            agent_install_authorized=False,
            restored_package_journal_clean=True,
            source_dirty_journal_preserved=True,
            interrupted_package_payload_absent=True,
            changed_source_interrupted_payload_preserved=True,
        )
        Path("evidence/package-root-recovery.json").write_text(
            json.dumps(package_source, indent=2) + "\n"
        )
        report = {
            "root_mount": mount,
            "boot_id": boot_id,
            "source_boot_id": source["source_boot_id"],
            "restored_sentinel": restored,
            "preserved_changed_root_sentinel": changed,
            "snapshot_id": source["snapshot_id"],
            "snapshot_mount": snapshot_mount,
            "package_recovery": package_source,
            "package_change_recovery_verified": True,
            "physical_recovery_verified": False,
            "firmware_installer_verified": False,
        }
        Path("evidence/root-recovery.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        subprocess.run(["umount", "/mnt/mano-root"], check=True)


if __name__ == "__main__":
    main()
