import tempfile
import unittest
from pathlib import Path

from mano_broker.control import dispatch_control
from mano_broker.core_cycles import CoreCycles
from mano_broker.ipc import Peer, dispatch
from mano_broker.prompts import Prompts
from mano_broker.protocol import canonical
from mano_broker.state import Denied, State


class CoreCycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.state.db.execute("INSERT INTO meta VALUES('native_generation',0)")
        self.queue = CoreCycles(self.state)
        self.prompt = Prompts(self.state).submit(human_uid=1002, request_key='a' * 32,
            prompt='human goal', boot_id='boot')['id']

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def claim(self, now=10, model='synthetic'):
        return self.queue.claim(human_uid=1002, model=model, max_output_tokens=100,
                                now=now, boot_id='boot')

    def finish(self, claim, status='awaiting_model_grant', now=12):
        return self.queue.finish(human_uid=1002, prompt_id=claim['prompt_id'],
            nonce=claim['nonce'], status=status, now=now, boot_id='boot')

    def attach(self):
        prompts = Prompts(self.state)
        prompts.claim(self.prompt, human_uid=1002, boot_id='boot')
        task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
            resource_id='b' * 32, classification='internal', boot_id='boot')
        prompts.attach(self.prompt, task, human_uid=1002, boot_id='boot')

    def test_atomic_claim_cooldown_and_original_model_without_authority(self):
        claim = self.claim()
        self.assertEqual(claim['prompt_id'], self.prompt)
        self.assertIsNone(self.claim())
        self.attach()
        self.finish(claim)
        self.assertIsNone(self.claim(now=16))
        self.assertIsNone(self.claim(now=17, model='changed'))
        second = self.claim(now=17)
        self.assertEqual(second['prompt_state'], 'task_created')
        self.assertNotEqual(second['nonce'], claim['nonce'])
        with self.assertRaises(Denied):
            self.finish(claim, now=18)
        self.finish(second, status='model_unknown_effect', now=18)
        self.assertIsNone(self.claim(now=100))
        for table in ('grants', 'actions', 'provider_jobs'):
            count = self.state.db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
            self.assertEqual(count, 0)

    def test_read_ready_settles_one_cycle_without_claiming_goal_completion(self):
        claim = self.claim()
        self.attach()
        self.finish(claim, status='read_ready')
        self.assertIsNone(self.claim(now=100))
        row = self.state.db.execute('SELECT state,status FROM core_cycles').fetchone()
        self.assertEqual(tuple(row), ('terminal', 'read_ready'))

    def test_restart_keeps_interrupted_claim_unknown_without_reallocation(self):
        self.claim()
        self.state.recover()
        self.assertIsNone(self.claim(now=100))
        self.assertEqual(tuple(self.state.db.execute(
            'SELECT state,status FROM core_cycles').fetchone()),
                         ('unknown', 'controller_uncertain'))

    def test_stop_rearm_never_restores_old_cycle(self):
        claim = self.claim()
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.finish(claim, status='controller_uncertain')
        self.state.db.execute("UPDATE meta SET value=0 WHERE key='latched'")
        self.state.db.execute("UPDATE meta SET value=1 WHERE key='native_generation'")
        self.assertIsNone(self.claim(now=100))

    def test_waiting_requires_attached_task_and_invalid_result_cannot_finish(self):
        claim = self.claim()
        with self.assertRaises(Denied):
            self.finish(claim)
        for change in ({'nonce': 'f' * 64}, {'human_uid': 1004}, {'status': 'approved'},
                       {'boot_id': 'different'}, {'now': 9}):
            args = dict(human_uid=1002, prompt_id=self.prompt, nonce=claim['nonce'],
                        status='controller_uncertain', now=12, boot_id='boot')
            with self.assertRaises(Denied):
                self.queue.finish(**(args | change))

    def test_root_claim_and_finish_are_denied_on_public_and_nonroot_channels(self):
        for operation, body in (
            ('claim_core_cycle', dict(human_uid=1002, model='synthetic', max_output_tokens=100)),
            ('finish_core_cycle', dict(human_uid=1002, prompt_id=self.prompt,
                                      nonce='f' * 64, status='completed')),
        ):
            packet = canonical(dict(schema_version='1.0', operation=operation, body=body)).encode()
            for uid in (1002, 1004):
                with self.assertRaises(Denied):
                    dispatch_control(self.state, packet, peer=Peer(42, uid, uid),
                                     now=10, boot_id='boot')
            with self.assertRaises(Denied):
                dispatch(self.state, packet, peer=Peer(42, 1004, 1004), now=10, boot_id='boot')
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM core_cycles').fetchone()[0], 0)

    def test_broker_recovery_invalidates_waiting_resource_authority(self):
        claim = self.claim()
        self.attach()
        self.finish(claim)
        self.state.recover()
        self.assertIsNone(self.claim(now=100))
        self.assertEqual(self.state.db.execute('SELECT state FROM core_cycles').fetchone()[0],
                         'unknown')

    def test_unverified_terminal_result_waits_for_journal_verification_without_core_polling(self):
        from mano_broker.protocol import ActionRequest

        claim = self.claim()
        self.attach()
        task = self.state.db.execute('SELECT task_id FROM human_prompts').fetchone()[0]
        args = dict(argv=['true'], cwd='.', timeout_seconds=1)
        grant = self.state.issue_grant(task, approved_human_uid=1002, approved_args=args,
            capability='terminal.run', resource_id='b' * 32, expires=100, max_count=1,
            memory_bytes=1048576, pids=4, cpu_percent=10, max_timeout_seconds=1)
        request = ActionRequest.parse(canonical(dict(schema_version='1.0', task_id=task,
            resource_id='b' * 32, grant_id=grant, capability='terminal.run', args=args,
            idempotency_key=self.prompt, reason='test')).encode())
        action, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id='boot')
        self.state.start(action['id'], now=11, boot_id='boot')
        self.state.transition(action['id'], 'done', exit_code=0)
        self.finish(claim, status='verifying')
        self.assertIsNone(self.claim(now=17))
        import hashlib

        artifact = b'checked result'
        digest = hashlib.sha256(artifact).hexdigest()
        self.state.db.execute('INSERT INTO artifacts VALUES(?,?,?,?)', (
            'e' * 32, action['id'], canonical(dict(size=len(artifact), sha256=digest)), artifact))
        self.state.record_verification(action['id'], checked_artifacts=[{
            'artifact_id': 'e' * 32, 'sha256': digest}])
        self.assertIsNotNone(self.claim(now=17))
