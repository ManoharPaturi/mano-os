import os
import socket
import tempfile
import unittest
from pathlib import Path

from mano_broker.ipc import Peer, dispatch, receive
from mano_broker.protocol import canonical
from mano_broker.state import Denied, State


class BrokerIPCTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / "broker")
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="auto",
            resource_id="a" * 32,
            classification="internal",
            boot_id="boot-a",
        )
        self.grant = self.state.issue_grant(
            self.task,
            approved_human_uid=1002,
            approved_args={"path": "file"},
            capability="files.read",
            resource_id="a" * 32,
            expires=100,
            max_count=2,
            memory_bytes=1024**2,
            pids=4,
            cpu_percent=10,
            max_timeout_seconds=10,
        )
        self.body = dict(
            schema_version="1.0",
            task_id=self.task,
            grant_id=self.grant,
            capability="files.read",
            resource_id="a" * 32,
            args={"path": "file"},
            idempotency_key="read",
            reason="test",
        )

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def call(self, operation="propose", body=None, uid=1004, **fields):
        packet = canonical(
            dict(
                schema_version="1.0", operation=operation, body=self.body if body is None else body
            )
            | fields
        ).encode()
        return dispatch(self.state, packet, peer=Peer(123, uid, 1004), now=10, boot_id="boot-a")

    def test_request_and_status_do_not_disclose_private_grant_or_arguments(self):
        result = self.call()
        self.assertTrue(result["fresh"])
        self.assertEqual(result["action"]["state"], "intent")
        self.assertFalse(result["action"]["verified"])
        self.assertEqual(set(result["action"]), {"id", "task_id", "state", "exit_code", "verified"})
        self.assertFalse(self.call()["fresh"])
        query = dict(task_id=self.task, action_id=result["action"]["id"])
        self.assertEqual(self.call("status", query)["action"], result["action"])
        with self.assertRaises(Denied):
            self.call("status", query, uid=1001)
        with self.assertRaises(Denied):
            self.call("status", query | {"task_id": "b" * 32})

    def test_no_wire_control_methods_or_caller_identity(self):
        for operation in ("issue_grant", "verify", "start", "emergency_stop", "rearm", "exec"):
            with self.subTest(operation=operation), self.assertRaises(Denied):
                self.call(operation)
        with self.assertRaises(Denied):
            self.call(uid=1001)
        with self.assertRaises(Denied):
            self.call(caller_uid=1004)
        with self.assertRaises(ValueError):
            self.call(body=self.body | {"caller_uid": 1004})
        for packet in (b"[]", b"{", b'{"operation":"x","operation":"y"}'):
            with self.assertRaises(ValueError):
                dispatch(self.state, packet, peer=Peer(1, 1004, 1004), now=10, boot_id="boot-a")
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM actions").fetchone()[0], 0)

    @unittest.skipUnless(hasattr(socket, "SO_PASSCRED"), "Linux kernel credentials only")
    def test_linux_transport_reads_actual_credentials_and_rejects_oversize(self):
        # Enable credentials before queueing, as the service listener must do.
        for packet, valid in ((b"{}", True), (b"x" * 65537, False)):
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                b.sendall(packet)
                if valid:
                    peer, data = receive(a)
                    self.assertEqual((peer.pid, peer.uid), (os.getpid(), os.getuid()))
                    self.assertEqual(data, packet)
                else:
                    with self.assertRaises(Denied):
                        receive(a)
            finally:
                a.close()
                b.close()

    def test_public_pending_request_has_no_nonce_and_cannot_self_approve(self):
        proposal = {key: value for key, value in self.body.items() if key != "grant_id"}
        pending = self.call("request_approval", proposal)
        self.assertTrue(pending["ok"])
        self.assertEqual(set(pending["approval"]), {"approval_id", "state", "grant_id"})
        self.assertIsNone(pending["approval"]["grant_id"])
        query = {"approval_id": pending["approval"]["approval_id"]}
        self.assertEqual(self.call("approval_status", query), pending)
        with self.assertRaises(Denied):
            self.call("approve", query)
        with self.assertRaises(Denied):
            self.call("approval_status", query, uid=1001)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], 1)
