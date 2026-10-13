import hashlib
import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State
from mano_broker.verifier import check, declare


class ExactFileVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='auto',
            resource_id='a' * 32, classification='internal', boot_id='boot')
        self.proposal = dict(schema_version='1.0', task_id=self.task, resource_id='a' * 32,
            capability='terminal.run', args=dict(argv=['true'], cwd='.', timeout_seconds=10),
            reason='Create exact file', idempotency_key='one')
        self.queue = Approvals(self.state)
        self.approval = self.queue.request(self.proposal, caller_uid=1004, now=10,
                                          boot_id='boot')['approval_id']
        self.data = b'expected source'
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.expected = dict(path='result', sha256=self.digest, size=len(self.data),
                             now=11, boot_id='boot')
        self.artifact = 'b' * 32

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def execute(self):
        view = self.queue.view(self.approval, human_uid=1002)
        grant = self.queue.approve(self.approval, authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'], now=12, boot_id='boot')
        request = ActionRequest.parse(canonical(self.proposal | {'grant_id': grant}).encode())
        action, _ = self.state.authorize(request, caller_uid=1004, now=12, boot_id='boot')
        self.action = action['id']
        self.state.start(self.action, now=12, boot_id='boot')
        self.state.transition(self.action, 'done', exit_code=0)
        metadata = dict(relative_path='result', size=len(self.data), sha256=self.digest)
        self.state.db.execute('INSERT INTO artifacts VALUES(?,?,?,?)',
            (self.artifact, self.action, canonical(metadata), self.data))

    def test_original_preapproval_contract_is_immutable_and_checks_actual_bytes(self):
        declare(self.state, self.approval, **self.expected)
        declare(self.state, self.approval, **self.expected)
        with self.assertRaises(Denied):
            declare(self.state, self.approval, **(self.expected | {'sha256': 'c' * 64}))
        self.execute()
        with self.assertRaises(Denied):
            declare(self.state, self.approval, **self.expected)
        with self.assertRaises(Denied):
            check(self.state, self.action, self.artifact, boot_id='other')
        altered = dict(relative_path='other', size=len(self.data), sha256=self.digest)
        self.state.db.execute('UPDATE artifacts SET metadata_json=?', (canonical(altered),))
        with self.assertRaises(Denied):
            check(self.state, self.action, self.artifact, boot_id='boot')
        altered['relative_path'] = 'result'
        self.state.db.execute('UPDATE artifacts SET metadata_json=?', (canonical(altered),))
        self.state.db.execute('UPDATE artifacts SET data=?', (b'wrong',))
        with self.assertRaises(Denied):
            check(self.state, self.action, self.artifact, boot_id='boot')
        self.assertEqual(self.state.db.execute('SELECT verified FROM actions').fetchone()[0], 0)
        self.state.db.execute('UPDATE artifacts SET data=?', (self.data,))
        self.assertTrue(check(self.state, self.action, self.artifact, boot_id='boot')['verified'])

    def test_no_posthoc_expectation_or_stopped_epoch_verification(self):
        self.execute()
        with self.assertRaises(Denied):
            check(self.state, self.action, self.artifact, boot_id='boot')
        with self.assertRaises(Denied):
            declare(self.state, self.approval, **self.expected)

    def test_expired_and_forged_expectations_are_denied(self):
        for update in (dict(path='../escape'), dict(size=True), dict(sha256='claim'),
                       dict(now=float('nan')), dict(now=100), dict(boot_id='other')):
            with self.subTest(update=update), self.assertRaises(ValueError):
                declare(self.state, self.approval, **(self.expected | update))
        declare(self.state, self.approval, **self.expected)
        self.execute()
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            check(self.state, self.action, self.artifact, boot_id='boot')
