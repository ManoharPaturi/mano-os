"""Ordinary unprivileged file identity tests; no Linux/Root/proc execution."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    "ci_runtime_inventory",
    Path(__file__).resolve().parents[1] / "scripts/probe_package_runtime_closure.py",
)
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


class MappedObjectIdentityTests(unittest.TestCase):
    def test_maps_padding_is_removed_for_kernel_map_files_lookup(self):
        self.assertEqual(INVENTORY.range_name("00400000-00420000"), "400000-420000")
        self.assertEqual(INVENTORY.range_name("0000000000000000-0000000000001000"), "0-1000")
        self.assertEqual(INVENTORY.range_name("7fc001000-7fc002000"), "7fc001000-7fc002000")

    def test_invalid_or_path_like_mapping_ranges_are_rejected(self):
        for value in (
            None,
            "",
            "../40-50",
            "0x40-0x50",
            "1-2/extra",
            "0-0",
            "10-1",
            "1-10000000000000000",
            "1-2-3",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                INVENTORY.range_name(value)

    def test_actual_descriptor_matches_file_without_assuming_maps_device(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "library"
            path.write_bytes(b"bounded ordinary test data")
            before = path.stat()
            with path.open("rb") as stream:
                mapped = os.fstat(stream.fileno())
                # Btrfs's /proc/maps superblock device can differ from stat's
                # subvolume device; it must not replace kernel-handle custody.
                maps_device = before.st_dev + 1
                self.assertNotEqual(maps_device, mapped.st_dev)
                INVENTORY.verify_mapping(before, mapped, before.st_ino)

    def test_same_bytes_in_another_inode_are_not_the_mapped_object(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = (Path(directory) / name for name in ("first", "second"))
            first.write_bytes(b"identical")
            second.write_bytes(first.read_bytes())
            with second.open("rb") as stream:
                with self.assertRaisesRegex(ValueError, "Mapped object"):
                    INVENTORY.verify_mapping(
                        first.stat(), os.fstat(stream.fileno()), first.stat().st_ino
                    )

    def test_changed_metadata_or_mapping_inode_is_rejected(self):
        fields = dict(st_dev=5, st_ino=9, st_size=16, st_mtime_ns=22, st_ctime_ns=24)
        original = SimpleNamespace(**fields)
        for key in fields:
            changed = SimpleNamespace(**(fields | {key: fields[key] + 1}))
            with self.subTest(field=key), self.assertRaises(ValueError):
                INVENTORY.verify_mapping(original, changed, 9)
        with self.assertRaises(ValueError):
            INVENTORY.verify_mapping(original, original, 10)
