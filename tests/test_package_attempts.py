import contextlib
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_attempts as attempts
from mano_runtime import recovery

BOOT = "01234567-89ab-cdef-0123-456789abcdef"
ATTEMPT = "a" * 32
RECOVERY = "b" * 32
DIGEST = hashlib.sha256(b"package database").hexdigest()


class PackageAttemptTests(unittest.TestCase):
    """State/crash-format tests; Root filesystem custody is exercised in CI."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name) / "attempts"
        for target, kwargs in (
            ("BASE", dict(new=self.base)),
            ("guard", dict(return_value=None)),
            ("boot", dict(return_value=BOOT)),
            ("trusted", dict(return_value=None)),
            ("read", dict(side_effect=lambda path, maximum: path.read_bytes())),
        ):
            self.addCleanup(patch.stopall)
            patch.object(attempts, target, **kwargs).start()
        for target, kwargs in (
            ("layout", dict(return_value={"root_uuid": BOOT})),
            ("locked", dict(side_effect=contextlib.nullcontext)),
            ("require_locked", dict(return_value=None)),
            ("current_status", dict(return_value=DIGEST)),
            ("subvolume", dict(return_value={"uuid": BOOT})),
            ("command", dict(return_value="ro=true")),
            ("read", dict(return_value=b"package database")),
            (
                "recovery_record",
                dict(
                    return_value=dict(
                        status_sha256=DIGEST,
                        boot_id=BOOT,
                        layout={"root_uuid": BOOT},
                        snapshot_number=1,
                        snapshot={"uuid": BOOT},
                    )
                ),
            ),
        ):
            patch.object(recovery, target, **kwargs).start()

    def begin(self):
        return attempts.begin(ATTEMPT, DIGEST, RECOVERY)

    def test_identity_reserved_across_lost_acknowledgement(self):
        intent = self.begin()
        with self.assertRaises(FileExistsError):
            self.begin()
        result = attempts.reconcile()
        self.assertEqual(result[0]["intent"], intent)
        self.assertEqual(result[0]["outcome"]["state"], "unknown")
        self.assertIs(result[0]["outcome"]["automatic_replay_allowed"], False)
        self.assertEqual(result, attempts.reconcile())
        with self.assertRaises(FileExistsError):
            self.begin()

    def test_intent_creation_failure_reserves_identity_and_blocks_inspection(self):
        with patch.object(recovery, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.begin()
        with self.assertRaises(FileExistsError):
            self.begin()
        with self.assertRaises(ValueError):
            attempts.reconcile()

    def test_partial_outcome_is_preserved_and_never_overwritten(self):
        self.begin()
        path = self.base / ATTEMPT / "unknown.json"
        path.write_bytes(b'{"state":')
        with self.assertRaises(ValueError):
            attempts.reconcile()
        self.assertEqual(path.read_bytes(), b'{"state":')

    def test_foreign_files_and_overshared_directories_fail_closed(self):
        self.begin()
        directory = self.base / ATTEMPT
        directory.chmod(0o755)
        with self.assertRaises(ValueError):
            attempts.reconcile()
        directory.chmod(0o700)
        (directory / "unexpected").touch()
        with self.assertRaises(ValueError):
            attempts.reconcile()

    def test_stale_checkpoint_or_changed_root_rejected_before_reservation(self):
        for change in (
            dict(status_sha256="d" * 64),
            dict(boot_id="other"),
            dict(layout={"root_uuid": "other"}),
        ):
            with self.subTest(change=change):
                saved = recovery.recovery_record.return_value.copy()
                saved.update(change)
                with patch.object(recovery, "recovery_record", return_value=saved):
                    with self.assertRaises(ValueError):
                        self.begin()
                self.assertFalse(self.base.exists())

    def test_checkpoint_identity_and_read_only_state_rechecked(self):
        with patch.object(recovery, "command", return_value="ro=false"):
            with self.assertRaises(ValueError):
                self.begin()
        self.assertFalse(self.base.exists())

    def test_malformed_and_authority_outcomes_refused(self):
        self.begin()
        outcome = attempts.reconcile()[0]["outcome"]
        path = self.base / ATTEMPT / "unknown.json"
        for value in (
            [],
            {**outcome, "automatic_replay_allowed": True},
            {**outcome, "state": "installed"},
            {**outcome, "extra": True},
            {**outcome, "observed_boot_id": "other"},
        ):
            with self.subTest(value=value):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    attempts.reconcile()

    def test_unknown_attempt_blocks_new_identity_without_deleting_evidence(self):
        self.begin()
        attempts.reconcile()
        with self.assertRaises(ValueError):
            attempts.begin("d" * 32, DIGEST, RECOVERY)
        self.assertEqual(list(self.base.iterdir()), [self.base / ATTEMPT])


class PackageAttemptGuardTests(unittest.TestCase):
    def test_mac_guard_precedes_any_root_observation(self):
        with (
            patch.object(attempts.sys, "platform", "darwin"),
            patch.object(recovery, "layout") as layout,
        ):
            with self.assertRaises(PermissionError):
                attempts.begin(ATTEMPT, DIGEST, RECOVERY)
            layout.assert_not_called()

    def test_nested_scope_never_opens_second_posix_descriptor(self):
        with patch.object(
            recovery, "_locked_descriptors", side_effect=contextlib.nullcontext
        ) as descriptors:
            with recovery.locked():
                with self.assertRaises(BlockingIOError):
                    with recovery.locked():
                        self.fail("Nested package-manager scope admitted")
            self.assertEqual(descriptors.call_count, 1)
            with recovery.locked():
                pass
            self.assertEqual(descriptors.call_count, 2)
