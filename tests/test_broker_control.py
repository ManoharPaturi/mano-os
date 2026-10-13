import tempfile
import unittest
from pathlib import Path

from mano_broker.approvals import Approvals
from mano_broker.control import dispatch_control
from mano_broker.ipc import Peer
from mano_broker.protocol import canonical
from mano_broker.state import Denied, State


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / "state")
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id="a" * 32,
            classification="internal",
            boot_id="boot-a",
        )
        self.queue = Approvals(self.state)
        self.pending = self.queue.request(
            dict(
                schema_version="1.0",
                task_id=self.task,
                capability="files.read",
                resource_id="a" * 32,
                args={"path": "file"},
                idempotency_key="read",
                reason="test",
            ),
            caller_uid=1004,
            now=10,
            boot_id="boot-a",
        )

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def call(self, operation, body, uid=0):
        return dispatch_control(
            self.state,
            canonical(dict(schema_version="1.0", operation=operation, body=body)).encode(),
            peer=Peer(123, uid, uid),
            now=11,
            boot_id="boot-a",
        )

    def test_root_only_view_and_one_confirmation_with_strict_schema(self):
        body = {"approval_id": self.pending["approval_id"], "human_uid": 1002}
        for uid in (1001, 1002, 1003, 1004):
            with self.assertRaises(Denied):
                self.call("approval_view", body, uid)
            with self.assertRaises(Denied):
                self.call("capture_artifact", {"action_id": "a" * 32, "path": "result"}, uid)
        view = self.call("approval_view", body)["view"]
        for operation in ("exec", "issue_grant", "stop", "rearm", "verify", "capture_artifact"):
            with self.assertRaises(Denied):
                self.call(operation, body)
        with self.assertRaises(Denied):
            self.call("approval_view", body | {"password": "unused"})
        confirmation = body | {"nonce": view["nonce"], "operation_digest": view["operation_digest"]}
        with self.assertRaises(Denied):
            self.call("confirm_approval", confirmation | {"human_uid": 1004})
        result = self.call("confirm_approval", confirmation)
        self.assertTrue(result["ok"])
        with self.assertRaises(Denied):
            self.call("confirm_approval", confirmation)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], 1)
