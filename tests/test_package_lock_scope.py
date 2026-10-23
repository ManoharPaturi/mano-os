import fcntl
import unittest
from unittest.mock import patch

from mano_runtime import package_attempts, recovery


class PackageLockScopeTests(unittest.TestCase):
    """Ordering/ownership tests; real dpkg and kernel owners are checked in CI."""

    def setUp(self):
        self.scope = recovery.PackageLocks(71)
        self.addCleanup(patch.stopall)
        patch.object(recovery, "root_guard").start()
        patch.object(recovery, "_ACTIVE_PACKAGE_SCOPE", self.scope).start()
        self.lockf = patch.object(recovery.fcntl, "lockf").start()

    def test_backend_handoff_requires_owned_scope_and_restores_backend(self):
        self.assertIs(recovery.require_locked(), self.scope)
        with self.scope.dpkg_backend() as env:
            self.assertEqual(env, {"DPKG_FRONTEND_LOCKED": "1"})
            self.assertFalse(self.scope.backend_held)
            with self.assertRaises(PermissionError):
                recovery.require_locked()
            with self.assertRaises(PermissionError):
                with self.scope.dpkg_backend():
                    self.fail("Nested handoff admitted")
        self.assertTrue(self.scope.backend_held)
        self.assertEqual(self.lockf.call_args_list[0].args, (71, fcntl.LOCK_UN))
        self.assertEqual(self.lockf.call_args_list[1].args, (71, fcntl.LOCK_EX | fcntl.LOCK_NB))

    def test_child_error_still_reacquires_backend(self):
        with self.assertRaisesRegex(ValueError, "Child failed"):
            with self.scope.dpkg_backend():
                raise ValueError("Child failed")
        self.assertIs(recovery.require_locked(), self.scope)
        self.assertEqual(self.lockf.call_count, 2)

    def test_failed_reacquire_never_marks_scope_ready(self):
        self.lockf.side_effect = [None, BlockingIOError("Backend still held")]
        with self.assertRaises(BlockingIOError):
            with self.scope.dpkg_backend():
                pass
        self.assertFalse(self.scope.backend_held)
        with self.assertRaises(PermissionError):
            recovery.require_locked()

    def test_wrong_owner_or_closed_scope_cannot_release_backend(self):
        original = self.scope.owner
        for field, value in [
            ("owner", (-1, original[1])),
            ("owner", (original[0], -1)),
            ("active", False),
        ]:
            with self.subTest(field=field, value=value), patch.object(self.scope, field, value):
                with self.assertRaises(PermissionError):
                    with self.scope.dpkg_backend():
                        self.fail("Invalid owner admitted")
        self.lockf.assert_not_called()

    def test_locked_operations_refuse_before_layout_when_no_scope(self):
        with (
            patch.object(recovery, "_ACTIVE_PACKAGE_SCOPE", None),
            patch.object(package_attempts, "guard"),
            patch.object(recovery, "layout") as layout,
        ):
            with self.assertRaises(PermissionError):
                recovery.create_locked()
            with self.assertRaises(PermissionError):
                package_attempts.begin_locked("a" * 32, "b" * 64, "c" * 32)
            layout.assert_not_called()
