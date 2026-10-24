import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_attempts as attempts
from mano_runtime import package_operator as operator
from mano_runtime import recovery


class OperatorRecoveryTests(unittest.TestCase):
    def setUp(self):
        from test_package_attempts import PackageAttemptTests

        self.fixture = PackageAttemptTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        for name, options in (('guard', dict(return_value=None)),
                ('read', dict(side_effect=lambda path, maximum: path.read_bytes()))):
            mocked = patch.object(operator.recovery if name == 'guard' else operator,
                                  name, **options)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.fixture.begin()
        self.attempt = 'a' * 32
        self.checkpoint = 'b' * 32
        self.directory = self.fixture.base / self.attempt

    def acknowledge(self, text):
        with patch('builtins.input', return_value=text), contextlib.redirect_stdout(io.StringIO()):
            return operator.acknowledge(self.attempt, self.checkpoint)

    def test_explicit_ack_preserves_unknown_and_allows_only_a_different_attempt(self):
        old = attempts.reconcile()
        data = (self.directory / 'unknown.json').read_bytes()
        receipt = self.acknowledge(operator.ACK)
        self.assertFalse(receipt['installation_authorized'])
        self.assertFalse(receipt['effects_reversed_verified'])
        self.assertEqual((self.directory / 'unknown.json').read_bytes(), data)
        current = attempts.reconcile()
        self.assertEqual(current[0]['outcome'], old[0]['outcome'])
        self.assertEqual(current[0]['operator_resolution'], receipt)
        with self.assertRaises(FileExistsError):
            self.fixture.begin()
        next_attempt = attempts.begin('d' * 32, receipt['request_sha256'], self.checkpoint)
        self.assertEqual(next_attempt['state'], 'intent')

    def test_cancellation_keeps_unknown_blocking_and_does_not_write_ack(self):
        with self.assertRaises(PermissionError):
            self.acknowledge('no')
        self.assertFalse((self.directory / 'operator.json').exists())
        with self.assertRaises(ValueError):
            attempts.begin('d' * 32, 'e' * 64, self.checkpoint)

    def test_changed_database_is_not_acknowledged_against_old_checkpoint(self):
        recovery.current_status.return_value = 'e' * 64
        with self.assertRaises(ValueError):
            self.acknowledge(operator.ACK)
        self.assertFalse((self.directory / 'operator.json').exists())

    def test_corrupt_operator_record_never_unblocks_new_attempts(self):
        self.acknowledge(operator.ACK)
        path = self.directory / 'operator.json'
        value = json.loads(path.read_text())
        value['automatic_replay_allowed'] = True
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            attempts.reconcile()
        with self.assertRaises(ValueError):
            attempts.begin('d' * 32, 'e' * 64, self.checkpoint)


class OperatorBoundaryTests(unittest.TestCase):
    def test_mac_guard_precedes_retirement_or_acknowledgement(self):
        with patch.object(recovery.sys, 'platform', 'darwin'):
            for call in (lambda: operator.acknowledge('a'*32, 'b'*32),
                         lambda: operator.retire('b'*32)):
                with self.assertRaises(PermissionError):
                    call()

    def test_retired_checkpoint_remains_readable_without_an_active_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            retired = base / 'retired'
            retired.mkdir()
            identifier = 'b' * 32
            value = dict(recovery_id=identifier, snapshot_read_only=True, snapshot_number=12)
            (retired / (identifier + '.json')).write_text(json.dumps(value))
            with patch.object(recovery, 'BASE', base), patch.object(recovery, 'read',
                    side_effect=lambda path, maximum: path.read_bytes()):
                self.assertEqual(recovery.recovery_record(identifier), value)


    def test_explicit_retirement_preserves_metadata_and_snapshot_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            identifier = 'b' * 32
            value = dict(recovery_id=identifier, snapshot_read_only=True, snapshot_number=12)
            active = base / (identifier + '.json')
            active.write_text(json.dumps(value))
            snapshot = base / 'snapshot-content'
            snapshot.write_bytes(b'preserve this checkpoint payload')
            with patch.object(recovery, 'BASE', base), patch.object(recovery, 'read',
                    side_effect=lambda path, maximum: path.read_bytes()), \
                    patch.object(recovery, 'guard'), patch.object(recovery, 'layout'), \
                    patch.object(recovery, 'locked', side_effect=contextlib.nullcontext), \
                    patch.object(operator, 'trusted'), patch('builtins.input',
                    return_value=operator.RETIRE), contextlib.redirect_stdout(io.StringIO()):
                receipt = operator.retire(identifier)
                self.assertEqual(recovery.recovery_record(identifier), value)
            self.assertFalse(active.exists())
            self.assertEqual(json.loads((base/'retired'/active.name).read_text()), value)
            self.assertEqual(snapshot.read_bytes(), b'preserve this checkpoint payload')
            self.assertIs(receipt['snapshot_deleted'], False)
