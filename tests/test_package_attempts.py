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


    def complete_fixture(self):
        from test_package_plans import PackageProtocolTests
        from test_package_postconditions import status

        fixture = PackageProtocolTests()
        fixture.setUp()
        before = status('bash')
        after = before + status('sl', fixture.plan['changes'][0]['candidate'])
        plan = fixture.plan | dict(status_sha256=hashlib.sha256(before).hexdigest())
        recovery.current_status.return_value = plan['status_sha256']
        recovery.recovery_record.return_value['status_sha256'] = plan['status_sha256']
        recovery.read.side_effect = lambda path, maximum: (
            before if 'snapshot' in path.parts else after)
        self.begin()
        recovery.current_status.return_value = hashlib.sha256(after).hexdigest()
        return plan

    def test_verified_observation_is_durable_and_never_replayed(self):
        plan = self.complete_fixture()
        completed = attempts.complete_locked(ATTEMPT, DIGEST, plan)
        rows = attempts.reconcile()
        self.assertEqual(rows[0]['outcome'], completed)
        self.assertEqual(completed['state'], 'postconditions-verified')
        self.assertIs(completed['automatic_replay_allowed'], False)
        self.assertIs(completed['postconditions']['execution_authority_verified'], False)
        with self.assertRaises(ValueError):
            attempts.complete_locked(ATTEMPT, DIGEST, plan)
        self.assertEqual(attempts.reconcile(), rows)
        # This is history from the original boot, not proof of a later system state.
        with patch.object(attempts, 'boot', return_value='fedcba98-7654-3210-fedc-ba9876543210'):
            self.assertEqual(attempts.reconcile(), rows)

    def test_unknown_attempt_cannot_be_promoted_by_late_success(self):
        plan = self.complete_fixture()
        attempts.reconcile()
        with self.assertRaises(ValueError):
            attempts.complete_locked(ATTEMPT, DIGEST, plan)
        self.assertFalse((self.base / ATTEMPT / 'verified.json').exists())

    def test_failed_or_partial_completion_never_allows_another_effect(self):
        plan = self.complete_fixture()
        with patch.object(recovery, 'save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                attempts.complete_locked(ATTEMPT, DIGEST, plan)
        with self.assertRaises(ValueError):
            attempts.begin('d' * 32, DIGEST, RECOVERY)
        self.assertEqual(attempts.reconcile()[0]['outcome']['state'], 'unknown')

    def test_corrupt_verified_outcome_is_preserved_and_blocks_reconciliation(self):
        plan = self.complete_fixture()
        attempts.complete_locked(ATTEMPT, DIGEST, plan)
        path = self.base / ATTEMPT / 'verified.json'
        path.write_bytes(b'{"state":')
        with self.assertRaises(ValueError):
            attempts.reconcile()
        self.assertEqual(path.read_bytes(), b'{"state":')

    def test_new_attempt_can_follow_verified_history_but_never_reuse_id(self):
        plan = self.complete_fixture()
        attempts.complete_locked(ATTEMPT, DIGEST, plan)
        # Supply a fresh checkpoint over the new current status for the next attempt.
        after = recovery.read(Path('/var/lib/dpkg/status'), recovery.MAX_STATUS)
        recovery.recovery_record.return_value['status_sha256'] = hashlib.sha256(after).hexdigest()
        recovery.read.side_effect = lambda path, maximum: after
        with self.assertRaises(FileExistsError):
            attempts.begin(ATTEMPT, DIGEST, RECOVERY)
        next_intent = attempts.begin('d' * 32, DIGEST, RECOVERY)
        self.assertEqual(next_intent['state'], 'intent')
        self.assertEqual(len(attempts.reconcile()), 2)


    def test_completion_requires_current_boot_exact_request_and_owned_scope(self):
        plan = self.complete_fixture()
        with self.assertRaises(ValueError):
            attempts.complete_locked(ATTEMPT, 'e' * 64, plan)
        with patch.object(attempts, 'boot', return_value='fedcba98-7654-3210-fedc-ba9876543210'):
            with self.assertRaises(ValueError):
                attempts.complete_locked(ATTEMPT, DIGEST, plan)
        with patch.object(recovery, 'require_locked', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                attempts.complete_locked(ATTEMPT, DIGEST, plan)
        self.assertEqual({p.name for p in (self.base / ATTEMPT).iterdir()}, {'intent.json'})


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
