import unittest
from unittest.mock import patch

from mano_broker.credentials import drop
from mano_broker.state import Denied


class CredentialTransitionGuards(unittest.TestCase):
    def test_wrong_context_has_no_identity_effect(self):
        for platform, uid in (("darwin", 0), ("linux", 1004)):
            with (
                patch("mano_broker.credentials.sys.platform", platform),
                patch("mano_broker.credentials.os.geteuid", return_value=uid),
                patch("mano_broker.credentials.os.setgroups") as groups,
                patch("mano_broker.credentials.os.setgid") as gid,
                patch("mano_broker.credentials.os.setuid") as user,
            ):
                with self.assertRaises(Denied):
                    drop(action_id="a" * 32, caller_uid=1004, parent_pid=1)
                groups.assert_not_called()
                gid.assert_not_called()
                user.assert_not_called()
