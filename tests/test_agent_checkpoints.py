import importlib.util
import os
import unittest
from pathlib import Path

import test_agent_runtime as fixtures

from mano_core.checkpoints import Session

HAS_SQLITE = (importlib.util.find_spec('langgraph') is not None
              and importlib.util.find_spec('langgraph.checkpoint.sqlite') is not None)


@unittest.skipUnless(HAS_SQLITE and os.geteuid() != 0, 'Optional saver and non-root required')
class PersistentCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AgentRuntimeTests()
        self.fixture.setUp()
        self.directory = Path(self.fixture.temp.name).resolve() / 'private'
        self.model = self.fixture.runtime.model
        self.broker = self.fixture.runtime.broker

    def tearDown(self):
        self.fixture.tearDown()

    def open(self, model=None):
        return Session(self.directory, model or self.model, self.broker)

    def test_close_reopen_uses_persisted_proposal_and_current_journal_without_new_effect(self):
        session = self.open()
        pending = session.step(self.fixture.input)
        session.close()
        self.fixture.approve(pending)
        session = self.open(lambda _: self.fail('Saved proposal must not call model again'))
        queued = session.step(self.fixture.input)
        session.close()
        action = queued['action_id']
        self.fixture.journal.start(action, now=10, boot_id='boot')
        self.fixture.journal.transition(action, 'unknown')
        proposals = self.fixture.calls.count('propose')
        session = self.open()
        try:
            self.assertEqual(session.step(self.fixture.input)['status'], 'unknown_effect')
            self.assertEqual(self.fixture.calls.count('propose'), proposals)
            with self.assertRaises(ValueError):
                session.step(self.fixture.input | {'prompt': 'Changed task'})
        finally:
            session.close()
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory / 'graph.sqlite').stat().st_mode & 0o777, 0o600)

    def test_public_directory_symlink_and_hardlink_are_rejected(self):
        self.directory.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            self.open()
        self.directory.chmod(0o700)
        target = self.directory / 'other'
        target.write_bytes(b'')
        target.chmod(0o600)
        database = self.directory / 'graph.sqlite'
        database.symlink_to(target)
        with self.assertRaises(OSError):
            self.open()
        database.unlink()
        os.link(target, database)
        with self.assertRaises(ValueError):
            self.open()
