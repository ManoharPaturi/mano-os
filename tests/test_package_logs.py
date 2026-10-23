"""Ordinary temporary-file I/O checks; no native Root or VM execution."""

import contextlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_logs as logs


class PackageLogIOTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mano-unprivileged-log-test-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(logs.recovery, 'root_guard'))
        self.stack.enter_context(patch.object(logs.recovery, 'BASE', self.directory))
        self.stack.enter_context(patch.object(logs, 'BASE', self.directory / 'logs'))
        self.stack.enter_context(patch.object(logs.package_attempts, 'record', return_value={}))

        def owned(path, *, directory=False):
            info = path.lstat()
            if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode):
                raise PermissionError('Only this unprivileged test owns the fixture')
            if directory and not stat.S_ISDIR(info.st_mode):
                raise PermissionError('Test directory required')
            return info

        self.stack.enter_context(patch.object(logs, 'trusted', side_effect=owned))

    def test_private_modes_exact_streams_and_never_overwrite(self):
        identity = 'a' * 32
        with logs.capture(identity) as emit:
            emit('stdout', b'out\x00\xff')
            emit('stderr', b'err\n')
        directory = logs.BASE / identity
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for name, expected in (('stdout', b'out\x00\xff'), ('stderr', b'err\n')):
            path = directory / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_bytes(), expected)
        with self.assertRaises(FileExistsError), logs.capture(identity):
            self.fail('A repeated attempt replaced retained output')
        self.assertEqual((directory / 'stdout').read_bytes(), b'out\x00\xff')

    def test_byte_limit_retains_only_prior_bytes_and_closes_on_failure(self):
        with patch.object(logs, 'MAX_BYTES', 4):
            with self.assertRaises(ValueError), logs.capture('b' * 32) as emit:
                emit('stdout', b'1234')
                emit('stderr', b'excess')
        directory = logs.BASE / ('b' * 32)
        self.assertEqual((directory / 'stdout').read_bytes(), b'1234')
        self.assertEqual((directory / 'stderr').read_bytes(), b'')

    def test_widened_custody_mode_is_rejected_without_new_attempt(self):
        logs.BASE.mkdir(mode=0o700)
        logs.BASE.chmod(0o777)
        with self.assertRaises(PermissionError), logs.capture('c' * 32):
            self.fail('Widened log custody was accepted')
        self.assertEqual(list(logs.BASE.iterdir()), [])
