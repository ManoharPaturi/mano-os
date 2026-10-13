import unittest
from unittest.mock import patch

from mano_broker.ipc import Peer
from mano_broker.launch_admission import admit
from mano_broker.state import Denied


class LaunchAdmissionContext(unittest.TestCase):
    def test_nonroot_context_denied_before_account_or_descriptor_lookup(self):
        with (
            patch("mano_broker.launch_admission.os.geteuid", return_value=1004),
            patch("mano_broker.launch_admission.pwd.getpwnam") as lookup,
        ):
            with self.assertRaises(Denied):
                admit(b"{}", [], peer=Peer(1, 1004, 1004))
            lookup.assert_not_called()
