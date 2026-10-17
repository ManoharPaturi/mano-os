import errno
import io
import json
import socket
import unittest
from unittest.mock import patch

from mano_broker.controller_service import ROOT_CAPABILITIES, main, parse, verify_current


class ControllerServiceTests(unittest.TestCase):
    def test_policy_is_explicit_disabled_or_fixed_model_metadata_only(self):
        value = dict(schema_version='1.0', enabled=False, model=None, max_output_tokens=None)
        self.assertIsNone(parse(json.dumps(value).encode()))
        value.update(enabled=True, model='synthetic', max_output_tokens=100)
        self.assertEqual(parse(json.dumps(value).encode()), dict(model='synthetic',
                                                                max_output_tokens=100))
        for change in ({'api_key': 'forbidden'}, {'endpoint': 'https://untrusted.invalid'},
                       {'enabled': 1}, {'max_output_tokens': True}, {'schema_version': 'other'}):
            with self.assertRaises(ValueError):
                parse(json.dumps(value | change).encode())
        with self.assertRaises(ValueError):
            parse(json.dumps(value | {'enabled': False}).encode())

    def test_disabled_service_never_claims_or_allocates_and_enabled_runs_one_cycle(self):
        with (
            patch('mano_broker.controller_service.sys.argv', ['controller-service']),
            patch('mano_broker.controller_service.sys.stdout', io.StringIO()) as output,
            patch('mano_broker.controller_service.load', return_value=None) as policy,
            patch('mano_broker.controller_service.run_cycle', return_value=None) as cycle,
        ):
            self.assertEqual(main(), 0)
            self.assertEqual(json.loads(output.getvalue())['state'], 'disabled')
            cycle.assert_not_called()
            policy.return_value = dict(model='synthetic', max_output_tokens=100)
            self.assertEqual(main(), 0)
            cycle.assert_called_once_with(model='synthetic', max_output_tokens=100)

    def profile(self, **changes):
        fields = dict(NoNewPrivs='1', Seccomp='2', CapEff=f'{ROOT_CAPABILITIES:x}',
            CapPrm=f'{ROOT_CAPABILITIES:x}', CapBnd=f'{ROOT_CAPABILITIES:x}',
            CapAmb='0', CapInh='0')
        fields.update(changes)
        status = '\n'.join(f'{key}: {value}' for key, value in fields.items())
        return lambda path: status if str(path) == '/proc/self/status' else (
            '0::/mano.slice/mano-core.slice/mano-controller.service\n')

    def test_profile_probe_contract_without_writes_or_connections(self):
        from pathlib import Path

        reader = self.profile()
        def denied_open(path, flags):
            raise OSError(errno.ENOENT if path.endswith('/openai') else errno.EROFS, 'denied')

        with (
            patch('mano_broker.controller_service.sys.platform', 'linux'),
            patch('mano_broker.controller_service.os.getuid', return_value=0),
            patch('mano_broker.controller_service.os.geteuid', return_value=0),
            patch('mano_broker.controller_service.os.getegid', return_value=0),
            patch.object(Path, 'read_text', autospec=True, side_effect=reader),
            patch('mano_broker.controller_service.os.open', side_effect=denied_open) as opening,
            patch('mano_broker.controller_service.socket.socket',
                  side_effect=OSError(errno.EAFNOSUPPORT, 'denied')) as network,
        ):
            verify_current()
            self.assertEqual(opening.call_count, 4)
            network.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            opening.side_effect = None
            opening.return_value = 77
            with patch('mano_broker.controller_service.os.close') as close:
                with self.assertRaises(ValueError):
                    verify_current()
                close.assert_called_once_with(77)

    def test_nonroot_launch_fails_before_policy_or_socket_probes(self):
        with (
            patch('mano_broker.controller_service.sys.platform', 'linux'),
            patch('mano_broker.controller_service.os.getuid', return_value=1002),
            patch('mano_broker.controller_service.os.open') as opening,
            patch('mano_broker.controller_service.socket.socket') as network,
        ):
            with self.assertRaises(ValueError):
                verify_current()
            opening.assert_not_called()
            network.assert_not_called()

    def test_extra_capabilities_or_missing_guards_fail_before_policy_access(self):
        from pathlib import Path

        for change in ({'CapInh': f'{ROOT_CAPABILITIES:x}'},
                       {'CapAmb': f'{ROOT_CAPABILITIES:x}'},
                       {'CapBnd': f'{ROOT_CAPABILITIES | (1 << 21):x}'},
                       {'CapEff': '0'}, {'NoNewPrivs': '0'}, {'Seccomp': '0'}):
            with (
                self.subTest(change=change),
                patch('mano_broker.controller_service.sys.platform', 'linux'),
                patch('mano_broker.controller_service.os.getuid', return_value=0),
                patch('mano_broker.controller_service.os.geteuid', return_value=0),
                patch('mano_broker.controller_service.os.getegid', return_value=0),
                patch.object(Path, 'read_text', autospec=True, side_effect=self.profile(**change)),
                patch('mano_broker.controller_service.os.open') as opening,
            ):
                with self.assertRaisesRegex(ValueError, 'Root controller restrictions absent'):
                    verify_current()
                opening.assert_not_called()
