"""Compile embedded probe programs without running any host service operation."""

import ast
import unittest
from pathlib import Path


class EmbeddedVMProbeTests(unittest.TestCase):
    def test_broker_probe_clients_are_complete_python_programs(self):
        source = Path(__file__).resolve().parents[1] / 'scripts' / 'probe_broker_service.py'
        tree = ast.parse(source.read_text())
        expected = {'private_denial', 'client', 'native_client', 'agent_step_code', 'price_probe',
                    'provider_stop_probe', 'egress_disabled_probe', 'egress_tls_probe'}
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = {target.id for target in node.targets if isinstance(target, ast.Name)}
            for name in names & expected:
                self.assertIsInstance(node.value, ast.Constant)
                self.assertIsInstance(node.value.value, str)
                compile(node.value.value, f'{source.name}:{name}', 'exec')
                found.add(name)
        self.assertEqual(found, expected)
