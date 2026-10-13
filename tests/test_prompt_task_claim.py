import tempfile
import unittest
from pathlib import Path

from mano_broker.prompts import Prompts
from mano_broker.state import Denied, State


class PromptTaskClaims(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.queue = Prompts(self.state)
        self.prompt = self.queue.submit(human_uid=1002, request_key='a' * 32,
                                       prompt='goal', boot_id='boot')['id']
        self.binding = dict(human_uid=1002, boot_id='boot')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def task(self, human=1002):
        return self.state.create_task(human_uid=human, caller_uid=1005, mode='supervised',
            resource_id='b' * 32, classification='internal', boot_id='boot')

    def test_one_claim_and_exact_human_task_attachment_never_issue_grants(self):
        claimed = self.queue.claim(self.prompt, **self.binding)
        self.assertEqual(claimed, dict(id=self.prompt, prompt='goal'))
        with self.assertRaises(Denied):
            self.queue.claim(self.prompt, **self.binding)
        with self.assertRaises(Denied):
            self.queue.attach(self.prompt, self.task(1003), **self.binding)
        task = self.task()
        attached = self.queue.attach(self.prompt, task, **self.binding)
        self.assertEqual(attached['state'], 'task_created')
        self.assertEqual(self.queue.status(self.prompt, **self.binding)['task_id'], task)
        with self.assertRaises(Denied):
            self.queue.attach(self.prompt, task, **self.binding)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM grants').fetchone()[0], 0)

    def test_restart_and_stop_turn_claims_uncertain_and_forbid_reallocation(self):
        for transition in (self.state.recover, self.state.emergency_stop):
            self.queue.claim(self.prompt, **self.binding)
            transition()
            self.assertEqual(self.queue.status(self.prompt, **self.binding)['state'],
                             'unknown_task_creation')
            with self.assertRaises(Denied):
                self.queue.claim(self.prompt, **self.binding)
            with self.assertRaises(Denied):
                self.queue.attach(self.prompt, self.task(), **self.binding)
            self.state.db.execute("UPDATE human_prompts SET state='received'")

    def test_wrong_human_boot_and_explicit_uncertainty_are_denied_or_preserved(self):
        for update in (dict(human_uid=1003), dict(boot_id='other')):
            with self.assertRaises(Denied):
                self.queue.claim(self.prompt, **(self.binding | update))
        self.queue.claim(self.prompt, **self.binding)
        for _ in range(2):
            self.assertEqual(self.queue.uncertain(self.prompt, **self.binding)['state'],
                             'unknown_task_creation')
        with self.assertRaises(Denied):
            self.queue.claim(self.prompt, **self.binding)
