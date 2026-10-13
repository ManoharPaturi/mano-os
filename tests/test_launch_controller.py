import base64
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_broker.ipc import Peer
from mano_broker.launch_controller import Controller, Record
from mano_broker.protocol import canonical
from mano_broker.runner import ProcessResult
from mano_broker.state import Denied


class PrivateControllerGuards(unittest.TestCase):
    def setUp(self):
        self.controller = Controller(None)
        self.peer = Peer(200, 999, 999)
        self.child = Mock()
        self.child.state = "finished"
        self.child.result = ProcessResult("completed", 0, b"abcdef", b"")
        self.job = "a" * 32
        self.action = "b" * 32
        self.controller.records[self.job] = Record(self.action, self.peer, 500, self.child)
        self.body = dict(
            instance_id=self.controller.instance_id, job_id=self.job, action_id=self.action
        )

    def invoke(self, operation, body, peer=None, alive=True):
        with (
            patch("mano_broker.launch_controller.os.geteuid", return_value=0),
            patch(
                "mano_broker.launch_controller.pwd.getpwnam",
                return_value=SimpleNamespace(pw_uid=999, pw_gid=999),
            ),
            patch(
                "mano_broker.launch_controller.select.select",
                return_value=([] if alive else [500], [], []),
            ),
        ):
            return self.controller.dispatch(
                canonical(dict(schema_version="1.0", operation=operation, body=body)).encode(),
                peer=peer or self.peer,
            )

    def test_wrong_instance_owner_action_or_dead_pid_never_starts(self):
        cases = [
            (self.body | {"instance_id": "c" * 32}, self.peer, True),
            (self.body | {"action_id": "d" * 32}, self.peer, True),
            (self.body, Peer(201, 999, 999), True),
            (self.body, self.peer, False),
            (self.body | {"verified": True}, self.peer, True),
        ]
        for body, peer, alive in cases:
            with self.assertRaises(Denied):
                self.invoke("start", body, peer, alive)
        self.child.start.assert_not_called()

    def test_bounded_output_is_separate_from_verification(self):
        result = self.invoke(
            "read_output", self.body | {"stream": "stdout", "offset": 1, "length": 3}
        )
        self.assertEqual(base64.b64decode(result["data"]), b"bcd")
        self.assertFalse(result["effect_verified"])
        for extra in (
            {"stream": "stdout", "offset": True, "length": 3},
            {"stream": "stdout", "offset": 0, "length": 4097},
            {"stream": "environment", "offset": 0, "length": 3},
        ):
            with self.assertRaises(Denied):
                self.invoke("read_output", self.body | extra)

    def test_root_or_worker_is_not_private_broker(self):
        for peer in (Peer(200, 0, 0), Peer(200, 1005, 1005)):
            with self.assertRaises(Denied):
                self.invoke("status", self.body, peer)
