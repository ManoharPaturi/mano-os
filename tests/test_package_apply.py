import contextlib
import copy
import json
import sys
import unittest
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.package_apply import validate
from mano_broker.profiles import READ_ONLY, WORKSPACE
from mano_core.packages import PackageApply, apply_proposal
from mano_protocol.actions import ActionRequest, Capability, canonical
from mano_runtime import package_apply as root


class ApplyAuthorityTests(unittest.TestCase):
    def setUp(self):
        from test_package_plans import PackageInstallReviewTests

        self.fixture = PackageInstallReviewTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        f = self.fixture
        self.state = f.state
        self.scope = apply_proposal(task_id=f.task, resource_id=f.resource,
            forecast_action_id=f.action, plan_sha256=f.body['plan_sha256'],
            key='apply-owned', reason='Install this exact signed plan')
        self.patched = patch('mano_broker.package_apply.load', return_value=(None, f.catalog))
        self.patched.start()
        self.addCleanup(self.patched.stop)

    def request(self, grant='0' * 32, scope=None):
        return ActionRequest.parse(canonical((scope or self.scope) | dict(grant_id=grant)).encode())

    def test_only_owned_successful_full_forecast_can_enter_native_apply_view(self):
        plan = validate(self.state, self.request(), caller_uid=1004, boot_id='boot')
        self.assertEqual(plan, self.fixture.plan)
        for uid, boot in ((1002, 'boot'), (1004, 'other')):
            with self.assertRaises(ValueError):
                validate(self.state, self.request(), caller_uid=uid, boot_id=boot)
        changed = copy.deepcopy(self.scope)
        changed['args']['plan_sha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            validate(self.state, self.request(scope=changed), caller_uid=1004, boot_id='boot')

    def test_distinct_native_approval_binds_root_risk_and_exact_plan(self):
        approvals = Approvals(self.state)
        result = approvals.request(self.scope, caller_uid=1004, now=11, boot_id='boot')
        self.assertEqual(result['state'], 'pending')
        self.assertIsNone(result['grant_id'])
        view = approvals.view(result['approval_id'], human_uid=1002)
        scope = view['package_apply_scope']
        self.assertEqual(scope['plan'], self.fixture.plan)
        self.assertTrue(scope['system_root_operation'])
        self.assertFalse(scope['profile_auto_approval_allowed'])
        self.assertIsNone(scope['peak_space_bytes'])
        grant = approvals.approve(result['approval_id'], authenticated_human_uid=1002,
            nonce=view['nonce'], operation_digest=view['operation_digest'], now=12, boot_id='boot')
        action, fresh = self.state.authorize(self.request(grant), caller_uid=1004,
                                            now=13, boot_id='boot')
        self.assertTrue(fresh)
        duplicate, fresh = self.state.authorize(self.request(grant), caller_uid=1004,
                                               now=14, boot_id='boot')
        self.assertFalse(fresh)
        self.assertEqual(action['id'], duplicate['id'])
        self.assertNotIn(Capability.PACKAGE_APPLY, READ_ONLY | WORKSPACE)

    def test_a_trusted_library_grant_without_native_approval_origin_is_insufficient(self):
        grant = self.state.issue_grant(self.fixture.task, approved_human_uid=1002,
            approved_args=self.scope['args'], capability=Capability.PACKAGE_APPLY,
            resource_id=self.fixture.resource, expires=80, max_count=1,
            memory_bytes=512*1024**2, pids=64, cpu_percent=50, max_timeout_seconds=60)
        with self.assertRaisesRegex(ValueError, 'distinct fresh native approval'):
            self.state.authorize(self.request(grant), caller_uid=1004, now=13, boot_id='boot')
        row = self.state.db.execute('SELECT used FROM grants WHERE id=?', (grant,)).fetchone()
        self.assertEqual(row['used'], 0)

    def test_raw_paths_commands_flags_and_authority_claims_never_parse(self):
        for args in (self.scope['args'] | dict(argv=['dpkg']),
                     dict(path='/tmp/evil.deb'), self.scope['args'] | dict(approved=True)):
            altered = self.scope | dict(args=args)
            with self.assertRaises(ValueError):
                self.request(scope=altered)

    def test_sdk_never_retries_an_uncertain_apply(self):
        calls = []
        def client(value):
            calls.append(value)
            return dict(schema_version='1.0', ok=False)
        with self.assertRaises(ValueError):
            PackageApply.start(client, proposed=self.scope, grant_id='a' * 32)
        self.assertEqual(len(calls), 1)


class RootApplyAdmissionTests(unittest.TestCase):
    def test_partial_stderr_cannot_hide_a_valid_stdout_control_frame(self):
        # Ordinary unprivileged Python only: no namespace, native guard or package effect.
        witness = dict.fromkeys(('network_socket_denied', 'protected_code_readonly',
            'cgroup_control_readonly', 'host_shadow_hidden', 'approval_ipc_hidden',
            'protected_ancestors_mounted', 'no_new_privileges', 'seccomp_active',
            'native_stop_authority_readonly', 'runtime_infrastructure_readonly'), True)
        witness['namespaces'] = {kind: kind + ':[123]' for kind in
                                ('mnt', 'net', 'ipc', 'pid', 'cgroup')}
        witness['capabilities'] = dict.fromkeys(('CapEff', 'CapPrm', 'CapInh',
                                               'CapBnd', 'CapAmb'), 0xdb)
        witness['securebits'] = 43
        witness['run_device'] = 1
        program = ('import sys,time;sys.stdin.buffer.read();'
                   'sys.stderr.write("progress without newline");sys.stderr.flush();'
                   'time.sleep(.1);print(' + repr('MANO_PACKAGE_BOUNDARY=' +
                                                 json.dumps(witness)) + ',flush=True)')
        with patch.object(root, 'sandbox', return_value=[sys.executable, '-c', program]), \
                patch.object(root, 'observe'), \
                patch.object(root.package_logs, 'capture',
                    return_value=contextlib.nullcontext(lambda channel, data: None)), \
                patch.object(root, 'runtime_device', return_value=0), \
                patch.object(root.os, 'readlink', return_value='host-namespace'):
            digest, actual = root.run_child({}, [], {}, None)
        self.assertEqual(actual, witness)
        self.assertRegex(digest, '^[a-f0-9]{64}$')

    def test_launcher_diagnostics_never_echo_paths_or_untrusted_output(self):
        self.assertEqual(root.launcher_failure(
            b'bwrap: mknod /private/secret: Operation not permitted\n'),
            dict(operation='device-node', error='permission'))
        self.assertEqual(root.launcher_failure(b'script output contains a secret\n'),
                         dict(operation='unreported', error='other'))
        self.assertEqual(root.launcher_failure(b'bwrap: Invalid fd: private-value\n'),
                         dict(operation='descriptor', error='other'))
        self.assertEqual(root.launcher_failure(
            b'bwrap: Destination is not a directory /private/value\n'),
            dict(operation='destination-directory', error='other'))

    def test_mac_guard_precedes_filesystem_or_network_observation(self):
        with patch.object(root.recovery.sys, 'platform', 'darwin'):
            with patch.object(root, 'acquire') as acquisition:
                with self.assertRaises(PermissionError):
                    root.execute({})
                acquisition.assert_not_called()

    def test_archive_urls_cannot_redirect_to_private_or_credentialed_sources(self):
        self.assertEqual(root.archive_url('http://deb.debian.org/debian/pool/main/s/sl/sl.deb'),
                         'https://deb.debian.org/debian/pool/main/s/sl/sl.deb')
        for url in ('https://127.0.0.1/debian/pool/a.deb',
                    'https://deb.debian.org@evil.example/debian/pool/a.deb',
                    'https://user:password@deb.debian.org/debian/pool/a.deb',
                    'https://deb.debian.org:444/debian/pool/a.deb',
                    'https://deb.debian.org/debian/pool/%2e%2e/etc/shadow',
                    'https://deb.debian.org/debian/pool/a.deb?token=private'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                root.archive_url(url)
        with self.assertRaises(ValueError):
            root.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_worker_failure_retains_intent_without_publishing_success(self):
        from test_package_plans import PackageProtocolTests

        fixture = PackageProtocolTests()
        fixture.setUp()
        scope = unittest.mock.Mock()
        scope.dpkg_backend.side_effect = contextlib.nullcontext
        with contextlib.ExitStack() as stack:
            for name, options in (
                ('domain', dict(return_value=None)),
                ('decode', dict(return_value=(unittest.mock.Mock(digest='a'*64), fixture.plan))),
                ('observe', dict(return_value=None)), ('acquire', dict(return_value=None)),
                ('run_child', dict(side_effect=ValueError('worker interrupted'))),
            ):
                stack.enter_context(patch.object(root, name, **options))
            stack.enter_context(patch.object(root.recovery, 'layout',
                                            return_value=dict(free_bytes=8*1024**3)))
            stack.enter_context(patch.object(root.package_archives, 'verified_archives',
                side_effect=lambda plan: contextlib.nullcontext(dict(archives=[]))))
            stack.enter_context(patch.object(root.recovery, 'require_locked', return_value=scope))
            stack.enter_context(patch.object(root.recovery, 'create_locked',
                                             return_value=dict(recovery_id='b'*32)))
            stack.enter_context(patch.object(root.package_attempts, 'ensure_available_locked'))
            begin = stack.enter_context(patch.object(root.package_attempts, 'begin_locked'))
            complete = stack.enter_context(patch.object(root.package_attempts, 'complete_locked'))
            refresh = stack.enter_context(patch.object(root.package_catalog, 'build'))
            with self.assertRaisesRegex(ValueError, 'worker interrupted'):
                root.execute(dict(action_id='c'*32))
            begin.assert_called_once()
            complete.assert_not_called()
            refresh.assert_not_called()


class PackageNativeAuthorityTests(unittest.TestCase):
    def test_child_must_recheck_current_generation_and_bounded_deadline(self):
        from mano_protocol.stop_state import Snapshot
        from mano_runtime import package_apt

        with patch.object(package_apt, 'guard'), patch.object(package_apt.time, 'monotonic',
                return_value=100), patch.dict(package_apt.os.environ,
                dict(MANO_PACKAGE_GENERATION='3', MANO_PACKAGE_EXPIRES='130'), clear=True):
            with patch.object(package_apt, 'snapshot', return_value=Snapshot(3, False)):
                package_apt.authority()
            for state in (Snapshot(3, True), Snapshot(4, False)):
                with patch.object(package_apt, 'snapshot', return_value=state):
                    with self.assertRaises(PermissionError):
                        package_apt.authority()
            for expiry in ('nan', 'inf', '99', '161'):
                with patch.dict(package_apt.os.environ, dict(MANO_PACKAGE_EXPIRES=expiry)), \
                        patch.object(package_apt, 'snapshot', return_value=Snapshot(3, False)):
                    with self.assertRaises(PermissionError):
                        package_apt.authority()

    def test_stop_authority_is_mounted_readonly_not_writable_with_var_lib(self):
        with patch.object(root.Path, 'exists', return_value=True), \
                patch.object(root.Path, 'glob', return_value=[]):
            argv = root.sandbox([], dict(native_generation=3, expires=130))
        index = argv.index('/var/lib/mano-stopd')
        self.assertEqual(argv[index-1:index+2],
                         ['--ro-bind', '/var/lib/mano-stopd', '/var/lib/mano-stopd'])
        self.assertIn('MANO_PACKAGE_GENERATION', argv)
        self.assertIn('MANO_PACKAGE_EXPIRES', argv)
