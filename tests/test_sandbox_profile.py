import unittest
from unittest.mock import patch

from mano_broker.sandbox import command


class SandboxProfileGuards(unittest.TestCase):
    def test_root_or_nonlinux_never_compiles_or_checks_package(self):
        for platform, uid in (("darwin", 1004), ("linux", 0)):
            with (
                patch("mano_broker.sandbox.sys.platform", platform),
                patch("mano_broker.sandbox.os.geteuid", return_value=uid),
                patch("mano_broker.sandbox.require_patched") as package,
            ):
                with self.assertRaises(PermissionError):
                    command(3, 4, ["true"])
                package.assert_not_called()
