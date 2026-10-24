"""Unprivileged temporary-file locks; Root custody/OS guards explicitly mocked."""

import fcntl
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import package_apply, package_catalog

REAL_FSTAT = os.fstat


class CatalogReservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "catalog-data"
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(package_catalog, "BASE", self.base))
        stack.enter_context(patch.object(package_catalog, "guard"))
        stack.enter_context(patch("mano_broker.package_catalog.trusted"))

        def fixture_custody(fd):
            info = REAL_FSTAT(fd)
            return SimpleNamespace(st_uid=0, st_nlink=info.st_nlink, st_mode=info.st_mode)

        stack.enter_context(patch.object(package_catalog.os, "fstat", side_effect=fixture_custody))
        self.assertIsNone(package_catalog._RESERVED_LOCK)

    def test_reservation_excludes_other_refresh_and_closes_on_exception(self):
        with self.assertRaisesRegex(RuntimeError, "test fault"):
            with package_catalog.retention_slot():
                fd = package_catalog._RESERVED_LOCK
                self.assertTrue(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
                competing = os.open(self.base / "refresh.lock", os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(competing)
                raise RuntimeError("test fault")
        self.assertIsNone(package_catalog._RESERVED_LOCK)
        with self.assertRaises(OSError):
            REAL_FSTAT(fd)
        with package_catalog.retention_slot():
            pass

    def test_four_catalog_limit_is_unchanged_and_history_is_preserved(self):
        with package_catalog.retention_slot():
            pass
        for number in range(4):
            (self.base / "catalogs" / str(number)).mkdir()
        with self.assertRaisesRegex(ValueError, "retention exhausted"):
            with package_catalog.retention_slot():
                self.fail("Full retention must refuse before caller effects")
        self.assertEqual(
            sorted(p.name for p in (self.base / "catalogs").iterdir()), ["0", "1", "2", "3"]
        )
        self.assertIsNone(package_catalog._RESERVED_LOCK)

    def test_nested_or_unreserved_catalog_publication_is_refused(self):
        with self.assertRaisesRegex(PermissionError, "reservation required"):
            package_catalog.build_locked()
        with package_catalog.retention_slot():
            with self.assertRaisesRegex(PermissionError, "cannot be nested"):
                with package_catalog.retention_slot():
                    self.fail("Nested reservation admitted")

    def test_apply_reserves_capacity_before_acquisition_or_checkpoint(self):
        with (
            patch.object(package_apply, "domain"),
            patch.object(package_apply, "observe"),
            patch.object(
                package_apply,
                "decode",
                return_value=(None, dict(net_installed_bytes=0, download_bytes=0)),
            ),
            patch.object(
                package_apply.recovery, "layout", return_value=dict(free_bytes=10 * 1024**3)
            ),
            patch.object(
                package_apply.package_catalog,
                "retention_slot",
                side_effect=ValueError("Catalog retention exhausted"),
            ),
            patch.object(package_apply, "acquire") as acquire,
            patch.object(package_apply.recovery, "create_locked") as checkpoint,
        ):
            with self.assertRaisesRegex(ValueError, "retention exhausted"):
                package_apply.execute({})
            acquire.assert_not_called()
            checkpoint.assert_not_called()
