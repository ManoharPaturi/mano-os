import socket
import unittest
from unittest.mock import Mock

from mano_broker.pty_supervisor import receive
from mano_broker.state import Denied


class PrivatePTYPackets(unittest.TestCase):
    def test_malformed_worker_cannot_forward_rights_or_crash_root_with_non_object(self):
        connection = Mock()
        for packet, ancillary, flags in (
            (b'{"kind":"ready"}', [], socket.MSG_CTRUNC),
            (b'{"kind":"ready"}', [], socket.MSG_TRUNC),
            (b'{"kind":"ready"}', [(1, 1, b'rights')], 0),
            (b'[]', [], 0), (b'null', [], 0),
            (b'{"kind":"ready","kind":"finished"}', [], 0),
        ):
            connection.recvmsg.return_value = packet, ancillary, flags, None
            with self.assertRaises((Denied, ValueError)):
                receive(connection)
