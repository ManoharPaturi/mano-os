import ast
import unittest
from pathlib import Path

from mano_broker.protocol import ActionRequest as LegacyActionRequest
from mano_broker.state import Denied as LegacyDenied
from mano_protocol.actions import ActionRequest
from mano_protocol.errors import Denied


class PublicProtocolBoundary(unittest.TestCase):
    def test_core_and_public_protocol_do_not_import_broker_implementation(self):
        source = Path(__file__).resolve().parents[1] / 'src'
        for package in ('mano_core', 'mano_protocol'):
            for file in (source / package).glob('*.py'):
                for node in ast.walk(ast.parse(file.read_text())):
                    names = ([node.module] if isinstance(node, ast.ImportFrom)
                             else [item.name for item in node.names]
                             if isinstance(node, ast.Import) else [])
                    for name in names:
                        self.assertFalse(name and name.startswith('mano_broker'), str(file))

    def test_existing_broker_exports_preserve_public_types_and_error_identity(self):
        self.assertIs(LegacyActionRequest, ActionRequest)
        self.assertIs(LegacyDenied, Denied)
