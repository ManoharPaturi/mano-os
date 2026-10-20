import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import recovery

UUID = "01234567-89ab-cdef-0123-456789abcdef"


class RecoveryAdmissionTests(unittest.TestCase):
    def test_platform_guard_before_commands(self):
        with (
            patch.object(recovery.sys, "platform", "darwin"),
            patch.object(recovery, "command") as command,
        ):
            with self.assertRaises(PermissionError):
                recovery.create()
            command.assert_not_called()

    def test_missing_root_terminal_refuses_before_filesystem_observation(self):
        with (
            patch.object(recovery.sys, "platform", "linux"),
            patch.object(recovery.os, "getuid", return_value=0),
            patch.object(recovery.os, "geteuid", return_value=0),
            patch.object(
                recovery.platform,
                "freedesktop_os_release",
                return_value={"ID": "debian", "VERSION_ID": "13"},
            ),
            patch.object(recovery.os, "isatty", return_value=False),
            patch.object(recovery, "command") as command,
        ):
            with self.assertRaises(PermissionError):
                recovery.create()
            command.assert_not_called()

    def test_recovery_id_has_no_path_or_snapshot_selector(self):
        for invalid in ("../1", "/etc/shadow", "a" * 31, "A" * 32, "a" * 32 + ";id"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                recovery.recovery_record(invalid)

    def test_cli_has_no_apply_delete_or_boot_switch(self):
        for operation in ("install", "delete", "rollback", "reboot", "set-default"):
            with (
                patch.object(sys, "argv", ["recovery", operation]),
                patch("sys.stderr"),
                self.assertRaises(SystemExit) as result,
            ):
                recovery.main()
            self.assertEqual(result.exception.code, 2)


class RecoveryFstabTests(unittest.TestCase):
    def setUp(self):
        self.root = "UUID=" + UUID + " / btrfs defaults,subvol=@ 0 0"
        self.other = "UUID=" + UUID + " /.snapshots btrfs defaults,subvol=@snapshots 0 0"

    def test_only_fresh_clone_root_record_changes(self):
        original = "# Root configuration\n" + self.root + "\n" + self.other + "\n"
        value = recovery.recovery_fstab(original, UUID, "/@")
        self.assertIn("defaults,subvol=@recovery", value)
        self.assertIn(self.other, value)
        self.assertIn("# Root configuration", value)
        self.assertEqual(original.count("subvol=@recovery"), 0)

    def test_ambiguous_foreign_and_conflicting_root_options_denied(self):
        for text in (
            "# missing root\n",
            self.root + "\n" + self.root,
            self.root.replace("subvol=@", "subvol=@,subvol=@other"),
            self.root.replace("subvol=@", "subvolid=256"),
            self.root.replace("subvol=@", "subvol=@,subvolid=256"),
            self.root.replace(UUID, "fedcba98-7654-3210-fedc-ba9876543210"),
            self.root.replace("btrfs", "ext4"),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                recovery.recovery_fstab(text, UUID, "/@")


class RecoveryCoverageTests(unittest.TestCase):
    def layout(self, *, extra=None, nested="", free=2**31, storage_mode=0o700, separate_root=None):
        mounts = [
            dict(target="/", fstype="btrfs", fsroot="/@", uuid=UUID, options="rw,relatime"),
            dict(
                target="/.snapshots",
                fstype="btrfs",
                fsroot="/@snapshots",
                uuid=UUID,
                options="rw,relatime",
            ),
        ]
        if extra:
            mounts.append(extra)

        def command(*args):
            if args[0] == "/usr/bin/findmnt":
                return json.dumps({"filesystems": mounts})
            if args[1:3] == ("inspect-internal", "rootid"):
                return "257" if args[-1] == separate_root else "256"
            if args[1:3] == ("subvolume", "list"):
                return nested
            raise AssertionError(args)

        with (
            patch.object(recovery, "command", side_effect=command),
            patch.object(recovery, "trusted"),
            patch.object(recovery, "read", return_value=b'SUBVOLUME="/"\n'),
            patch.object(
                recovery.os, "statvfs", return_value=SimpleNamespace(f_bavail=free, f_frsize=1)
            ),
            patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=storage_mode)),
        ):
            return recovery.layout()

    def test_single_package_root_and_private_external_storage(self):
        observed = self.layout()
        self.assertEqual(observed["root_uuid"], UUID)
        self.assertEqual(observed["package_paths"], list(recovery.CRITICAL))

    def test_package_ancestor_descendant_mounts_and_nested_subvolumes_refused(self):
        for path in ("/usr", "/usr/local", "/var", "/var/lib/dpkg", "/boot/efi"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.layout(
                    extra=dict(target=path, fstype="tmpfs", fsroot="/", uuid=None, options="rw")
                )
        with self.assertRaises(ValueError):
            self.layout(separate_root="/var/lib/dpkg")
        for nested in (
            "ID 300 gen 22 top level 256 path @/usr/local",
            "ID 300 gen 22 top level 256 path @/var/lib/dpkg/hidden",
            "unknown output",
        ):
            with self.subTest(nested=nested), self.assertRaises(ValueError):
                self.layout(nested=nested)

    def test_low_space_and_public_snapshot_storage_refused(self):
        with self.assertRaises(ValueError):
            self.layout(free=2**30 - 1)
        with self.assertRaises(ValueError):
            self.layout(storage_mode=0o755)
