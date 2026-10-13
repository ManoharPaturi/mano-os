import array
import os
import socket
import unittest
from unittest.mock import Mock, patch

from mano_broker.ipc import CREDENTIALS, Peer
from mano_broker.launch_client import Client, reply
from mano_broker.protocol import canonical
from mano_broker.state import Denied


class LauncherReplyGuards(unittest.TestCase):
    def connection(self, *, packet=None, credentials=None, flags=0, extra=()):
        connection = Mock()
        if packet is None:
            packet = canonical(dict(schema_version="1.0", ok=True)).encode()
        connection.recvmsg.return_value = (
            packet,
            [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
              credentials if credentials is not None else CREDENTIALS.pack(200, 0, 0)), *extra],
            flags, None,
        )
        return connection

    @unittest.skipUnless(hasattr(socket, "SCM_CREDENTIALS"), "Linux credentials required")
    def test_message_identity_and_envelope(self):
        peer, result = reply(self.connection())
        self.assertEqual(peer, Peer(200, 0, 0))
        self.assertTrue(result["ok"])
        broker_reply = self.connection(credentials=CREDENTIALS.pack(300, 999, 999))
        broker_peer, _ = reply(broker_reply, expected_uid=999, expected_gid=999)
        self.assertEqual(broker_peer, Peer(300, 999, 999))
        with self.assertRaises(Denied):
            reply(broker_reply)  # Root launcher identity remains the default.
        for kwargs in (
            dict(credentials=CREDENTIALS.pack(200, 999, 999)),
            dict(credentials=CREDENTIALS.pack(0, 0, 0)),
            dict(flags=socket.MSG_TRUNC),
            dict(flags=socket.MSG_CTRUNC),
            dict(packet=b'{"schema_version":"1.0","ok":1}'),
            dict(packet=b'{"schema_version":"1.0","ok":true,"ok":false}'),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises((Denied, ValueError)):
                reply(self.connection(**kwargs))

    @unittest.skipUnless(hasattr(socket, "SCM_CREDENTIALS"), "Linux credentials required")
    def test_unexpected_rights_are_closed_before_denial(self):
        read_fd, write_fd = os.pipe()
        try:
            connection = self.connection(extra=[
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [read_fd]).tobytes())
            ])
            with self.assertRaises(Denied):
                reply(connection)
            with self.assertRaises(OSError):
                os.fstat(read_fd)
        finally:
            os.close(write_fd)

    def test_dead_service_closed_client_and_unknown_channel_do_not_connect(self):
        client = Client()
        client.peer, client.pidfd = Peer(200, 0, 0), 50
        with patch("mano_broker.launch_client.select.select", return_value=([50], [], [])), \
             patch("mano_broker.launch_client.socket.socket") as connect:
            with self.assertRaises(Denied):
                client.exchange("control", {})
            connect.assert_not_called()
        client.pidfd = None
        client.close()
        with self.assertRaises(Denied):
            client.exchange("control", {})
        with self.assertRaises(Denied):
            Client().exchange("model-path", {})

    def test_control_never_transports_descriptors(self):
        with patch("mano_broker.launch_client.socket.socket") as connect:
            with self.assertRaises(Denied):
                Client().exchange("control", {}, [10, 11])
            connect.assert_not_called()
