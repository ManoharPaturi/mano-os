import contextlib
import hashlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from mano_runtime import package_archives as archives


class ArchiveAdmissionTests(unittest.TestCase):
    def setUp(self):
        from test_package_plans import PackageProtocolTests

        fixture = PackageProtocolTests()
        fixture.setUp()
        self.plan = fixture.plan

    def test_mac_guard_refuses_before_cache_observation(self):
        with patch.object(sys, "platform", "darwin"), patch.object(archives, "trusted") as trusted:
            with self.assertRaises(PermissionError):
                with archives.verified_archives(self.plan):
                    self.fail("Mac archive custody admitted")
            trusted.assert_not_called()

    def test_budget_failure_never_opens_cache(self):
        with (
            patch.object(archives, "current_plan", return_value=contextlib.nullcontext({})),
            patch.object(archives, "MAX_TOTAL", 1),
            patch.object(archives, "trusted") as trusted,
        ):
            with self.assertRaisesRegex(ValueError, "budget"):
                with archives.verified_archives(self.plan):
                    self.fail("Over-budget staging admitted")
            trusted.assert_not_called()

    def test_no_change_plan_yields_no_archive_or_install_authority(self):
        plan = self.plan | dict(changes=[], download_bytes=0)
        with (
            patch.object(
                archives,
                "current_plan",
                return_value=contextlib.nullcontext(dict(stop_generation=3)),
            ),
            patch.object(archives, "load"),
            patch.object(archives, "armed"),
            patch.object(archives, "trusted") as trusted,
        ):
            with archives.verified_archives(plan) as receipt:
                self.assertEqual(receipt["archives"], [])
                self.assertEqual(receipt["sealed_bytes"], 0)
                self.assertIs(receipt["install_authorized"], False)
                self.assertIsNone(receipt["peak_install_space_bytes"])
            trusted.assert_not_called()


@unittest.skipUnless(sys.platform == "linux", "Linux memfd seal semantics required")
class ArchiveSealTests(unittest.TestCase):
    def test_actual_kernel_seals_and_exact_copy_without_root(self):
        import errno

        data = b"exact archive bytes\x00\xff" * 1000
        with tempfile.TemporaryFile() as source, patch.object(archives, "armed"):
            source.write(data)
            source.seek(0)
            fd, digest = archives.copy_sealed(source.fileno(), len(data), 3)
            try:
                self.assertEqual(digest, hashlib.sha256(data).hexdigest())
                self.assertEqual(os.read(fd, len(data) + 1), data)
                with self.assertRaises(OSError) as failure:
                    os.write(fd, b"x")
                self.assertEqual(failure.exception.errno, errno.EPERM)
            finally:
                os.close(fd)

    def test_short_read_refused(self):
        with tempfile.TemporaryFile() as source, patch.object(archives, "armed"):
            source.write(b"x")
            source.seek(0)
            with self.assertRaisesRegex(ValueError, "size changed"):
                archives.copy_sealed(source.fileno(), 2, 3)
