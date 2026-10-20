import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State
from mano_protocol.profiles import configuration


class PermissionProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'broker')
        self.state.db.execute("INSERT INTO meta VALUES('native_generation',1)")
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
            resource_id='a'*32, classification='internal', boot_id='boot')
        self.queue = Approvals(self.state)
        self.serial = 0

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def proposal(self, capability, args):
        self.serial += 1
        return dict(schema_version='1.0', task_id=self.task, capability=capability,
            resource_id='a'*32, args=args, idempotency_key=f'p{self.serial}', reason='untrusted')

    def request(self, proposal, now=10):
        return self.queue.request(proposal, caller_uid=1004, now=now, boot_id='boot')

    def profile(self, mode='auto', duration=60, count=4, timeout=10, now=10):
        proposal = self.proposal('policy.set_profile', dict(mode=mode, duration_seconds=duration,
            max_actions=count, max_timeout_seconds=timeout))
        pending = self.request(proposal, now)
        self.assertEqual(pending['state'], 'pending')
        view = self.queue.view(pending['approval_id'], human_uid=1002)
        grant = self.queue.approve(pending['approval_id'], authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'],
            now=now+1, boot_id='boot')
        return grant

    def authorize(self, proposal, approved, now=12):
        request = ActionRequest.parse(
            canonical(proposal | dict(grant_id=approved['grant_id'])).encode())
        return self.state.authorize(request, caller_uid=1004, now=now, boot_id='boot')[0]

    def test_no_profile_before_pam_and_no_auto_elevation_budget_or_disclosure(self):
        write = self.proposal('files.write', dict(path='file', text='data'))
        self.assertEqual(self.request(write)['state'], 'pending')
        self.profile()
        for cap, args in (
            ('policy.set_profile', dict(mode='full-access', duration_seconds=30,
                max_actions=3, max_timeout_seconds=10)),
            ('model.set_budget', dict(money_micro_usd=100, tokens=100)),
            ('model.plan', dict(provider='openai', model='snapshot', prompt='private',
                               max_output_tokens=16)),
        ):
            self.assertEqual(self.request(self.proposal(cap, args))['state'], 'pending')
        with self.assertRaises(Denied):
            self.queue.approve(self.request(write)['approval_id'], authenticated_human_uid=1004,
                               nonce='x', operation_digest='x', now=12, boot_id='boot')

    def test_each_mode_has_distinct_admission_and_same_exact_resource_binding(self):
        cases = [('supervised', 'files.read', dict(path='file'), True),
                 ('supervised', 'files.write', dict(path='file', text='x'), False),
                 ('auto', 'terminal.run', dict(argv=['/usr/bin/python3', '-c', 'pass'],
                                              cwd='.', timeout_seconds=1), True),
                 ('auto', 'terminal.run', dict(argv=['/bin/sh', '-c', 'true'],
                                              cwd='.', timeout_seconds=1), False),
                 ('full-access', 'terminal.run', dict(argv=['/bin/sh', '-c', 'true'],
                                                     cwd='.', timeout_seconds=1), True),
                 ('full-access', 'terminal.run', dict(argv=['/workspace/tool'],
                                                     cwd='.', timeout_seconds=1), True)]
        for mode, cap, args, permitted in cases:
            self.profile(mode)
            proposal = self.proposal(cap, args)
            result = self.request(proposal, 12)
            self.assertEqual(result['state'], 'approved' if permitted else 'pending')
            if permitted:
                altered = proposal | dict(grant_id=result['grant_id'], resource_id='b'*32)
                with self.assertRaises(Denied):
                    self.state.authorize(ActionRequest.parse(canonical(altered).encode()),
                                         caller_uid=1004, now=12, boot_id='boot')

    def test_count_idempotence_and_exact_arguments_cannot_be_amplified(self):
        self.profile(count=1)
        proposal = self.proposal('files.write', dict(path='file', text='x'))
        result = self.request(proposal, 12)
        self.assertEqual(result['state'], 'approved')
        self.assertEqual(self.request(proposal, 12), result)
        remaining = self.state.db.execute('SELECT remaining FROM task_profiles').fetchone()[0]
        self.assertEqual(remaining, 0)
        action = self.authorize(proposal, result)
        self.assertEqual(action['state'], 'intent')
        changed = proposal | dict(args=dict(path='other', text='x'), idempotency_key='changed',
                                  grant_id=result['grant_id'])
        with self.assertRaises(Denied):
            self.state.authorize(ActionRequest.parse(canonical(changed).encode()),
                                 caller_uid=1004, now=12, boot_id='boot')
        self.assertEqual(self.request(self.proposal('files.read', dict(path='other')), 12)['state'],
                         'pending')

    def test_expiry_generation_restart_stop_and_replacement_revoke_authority(self):
        for fault in ('expiry', 'generation', 'restart', 'stop', 'replacement'):
            self.profile(now=10)
            proposal = self.proposal('files.read', dict(path='file'))
            grant = self.request(proposal, 12)
            if fault == 'expiry':
                now = 72
            else:
                now = 13
                if fault == 'generation':
                    self.state.db.execute(
                        "UPDATE meta SET value=value+1 WHERE key='native_generation'")
                elif fault == 'restart':
                    self.state.recover()
                elif fault == 'stop':
                    self.state.emergency_stop()
                else:
                    self.profile('supervised', now=12)
            with self.subTest(fault=fault), self.assertRaises(Denied):
                self.authorize(proposal, grant, now)
            # Fresh fixture for the next independent fault, without rearming/reusing authority.
            self.state.close()
            self.state = State(Path(self.temp.name).resolve() / fault)
            self.state.db.execute("INSERT INTO meta VALUES('native_generation',1)")
            self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
                resource_id='a'*32, classification='internal', boot_id='boot')
            self.queue = Approvals(self.state)

    def test_profile_change_requires_idle_task_and_queued_dispatch_rechecks_generation(self):
        self.profile()
        proposal = self.proposal('files.read', dict(path='file'))
        grant = self.request(proposal, 12)
        action = self.authorize(proposal, grant)
        self.state.db.execute("UPDATE meta SET value=2 WHERE key='native_generation'")
        with self.assertRaises(Denied):
            self.state.start(action['id'], now=13, boot_id='boot')
        self.state.db.execute("UPDATE meta SET value=1 WHERE key='native_generation'")
        self.state.start(action['id'], now=13, boot_id='boot')
        with self.assertRaises(Denied):
            self.profile('full-access', now=13)

    def test_invalid_bounds_and_live_resource_paths_are_not_profile_options(self):
        base = dict(mode='auto', duration_seconds=30, max_actions=3, max_timeout_seconds=10)
        for changed in (dict(mode='root'), dict(max_actions=True), dict(max_actions=33),
                        dict(duration_seconds=901), dict(max_timeout_seconds=301),
                        dict(paths=['/etc']), dict(network=True),
                        dict(mode='full-access', duration_seconds=301)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                configuration(base | changed)

    def test_package_forecast_needs_separate_consent_and_refuses_stale_catalog(self):
        self.profile('full-access')
        catalog = dict(catalog_id='f'*64,architecture='amd64',expires_at=5000)
        proposed = self.proposal('packages.plan_install',dict(names=['sl'],catalog_id='f'*64))
        with patch('mano_broker.package_catalog.load',return_value=(None,catalog)):
            pending = self.request(proposed,12)
            self.assertEqual(pending['state'],'pending')
            self.assertIsNone(pending['grant_id'])
            self.assertEqual(self.state.db.execute(
                'SELECT remaining FROM task_profiles').fetchone()[0],4)
            view = self.queue.view(pending['approval_id'],human_uid=1002)
            self.assertFalse(view['package_scope']['installation_authorized'])
            self.assertEqual(view['args'],proposed['args'])
            grant = self.queue.approve(pending['approval_id'],authenticated_human_uid=1002,
                nonce=view['nonce'],operation_digest=view['operation_digest'],now=13,boot_id='boot')
            changed = proposed|dict(grant_id=grant,args=dict(names=['bash'],catalog_id='f'*64))
            with self.assertRaises(Denied):
                self.state.authorize(ActionRequest.parse(canonical(changed).encode()),
                    caller_uid=1004,now=14,boot_id='boot')
            request = ActionRequest.parse(canonical(proposed|dict(grant_id=grant)).encode())
            with patch('mano_broker.package_catalog.load',side_effect=ValueError('stale catalog')):
                with self.assertRaises(ValueError):
                    self.state.authorize(request,caller_uid=1004,now=14,boot_id='boot')
            self.assertEqual(self.state.db.execute('SELECT used FROM grants WHERE id=?',
                                                  (grant,)).fetchone()[0],0)
            self.state.emergency_stop()
            with self.assertRaises(Denied):
                self.state.authorize(request,caller_uid=1004,now=14,boot_id='boot')
