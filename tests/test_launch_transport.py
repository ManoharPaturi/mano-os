import unittest
from unittest.mock import patch

from mano_broker.launch_transport import activated_listeners
from mano_broker.state import Denied


class LauncherActivationGuards(unittest.TestCase):
    def test_wrong_identity_or_fd_count_never_wraps_sockets(self):
        for uid, values in ((1005, {}), (0, {"LISTEN_PID": "123", "LISTEN_FDS": "3"})):
            with (
                patch("mano_broker.launch_transport.os.geteuid", return_value=uid),
                patch("mano_broker.launch_transport.os.getpid", return_value=123),
                patch.dict("mano_broker.launch_transport.os.environ", values, clear=True),
                patch("mano_broker.launch_transport.socket.socket") as wrapping,
            ):
                with self.assertRaises(Denied):
                    activated_listeners()
                wrapping.assert_not_called()
