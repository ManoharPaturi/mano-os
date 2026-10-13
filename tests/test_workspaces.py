import unittest
from unittest.mock import patch

from mano_broker.workspaces import create_workspace


class WorkspaceCreatorGuards(unittest.TestCase):
    def test_nonroot_and_nonlinux_do_not_touch_filesystem(self):
        for platform, uid in (("darwin", 0), ("linux", 1004)):
            with (
                patch("mano_broker.workspaces.sys.platform", platform),
                patch("mano_broker.workspaces.os.geteuid", return_value=uid),
                patch("mano_broker.workspaces.Path.mkdir") as mkdir,
            ):
                with self.assertRaises(PermissionError):
                    create_workspace(human_uid=1002, caller_uid=1004)
                mkdir.assert_not_called()
