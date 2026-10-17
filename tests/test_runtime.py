import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_broker.approvals import Approvals
from mano_broker.ipc import Peer
from mano_broker.protocol import canonical
from mano_broker.provision import provision_task
from mano_broker.runtime import Runtime
from mano_broker.state import Denied, State


@unittest.skipUnless(sys.platform == "linux", "Linux live resource runtime required")
class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "workspace"
        self.root.mkdir(mode=0o770)
        self.root.chmod(0o770)
        (self.root / "file").write_text("original")
        self.state = State(self.base / "state")
        self.runtime = Runtime(self.state, boot_id="boot-a")
        fd = os.open(self.root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with patch(
                "mano_broker.provision.pwd.getpwuid",
                return_value=SimpleNamespace(pw_gid=os.getgid()),
            ):
                result = provision_task(
                    self.state,
                    self.runtime.registry,
                    canonical(
                        dict(
                            schema_version="1.0",
                            operation="provision_task",
                            body=dict(
                                human_uid=1002,
                                caller_uid=1004,
                                mode="supervised",
                                classification="internal",
                            ),
                        )
                    ).encode(),
                    peer=Peer(123, 0, 0),
                    directory_fd=fd,
                    boot_id="boot-a",
                )
        finally:
            os.close(fd)
        self.body = dict(
            schema_version="1.0",
            task_id=result["task_id"],
            resource_id=result["resource_id"],
            capability="files.read",
            args={"path": "file"},
            idempotency_key="read",
            reason="test",
        )

    def tearDown(self):
        self.runtime.close()
        self.state.close()
        self.temp.cleanup()

    def call(self, operation, body=None, uid=1004, now=10):
        return self.runtime.dispatch(
            canonical(
                dict(
                    schema_version="1.0",
                    operation=operation,
                    body=self.body if body is None else body,
                )
            ).encode(),
            peer=Peer(124, uid, uid),
            now=now,
        )

    def approved(self):
        pending = self.call("request_approval")["approval"]
        queue = Approvals(self.state)
        view = queue.view(pending["approval_id"], human_uid=1002)
        grant = queue.approve(
            pending["approval_id"],
            authenticated_human_uid=1002,
            nonce=view["nonce"],
            operation_digest=view["operation_digest"],
            now=11,
            boot_id="boot-a",
        )
        return self.body | {"grant_id": grant}

    def test_propose_prepares_before_journal_replay_without_another_fd(self):
        body = self.approved()
        first = self.call("propose", body, now=12)
        self.assertTrue(first["fresh"])
        lease = self.runtime.registry.leases[first["action"]["id"]]
        self.assertEqual(lease.descriptors["target"].inode, (self.root / "file").stat().st_ino)
        self.assertFalse(self.call("propose", body, now=12)["fresh"])
        self.assertEqual(len(self.runtime.registry.leases), 1)
        for change in ({"task_id": []}, {"resource_id": {}}, {"resource_id": "b" * 32}):
            with self.assertRaises(ValueError):
                self.call("request_approval", self.body | change)
        with self.assertRaises(Denied):
            self.call("request_approval", uid=1001)

    def test_restart_revokes_resources_grants_and_unprepared_intents(self):
        body = self.approved()
        first = self.call("propose", body, now=12)
        self.runtime.close()
        self.runtime = Runtime(self.state, boot_id="boot-a")
        self.assertEqual(
            self.call("status", {"task_id": body["task_id"], "action_id": first["action"]["id"]})[
                "action"
            ]["state"],
            "failed",
        )
        with self.assertRaises(Denied):
            self.call("propose", body, now=12)
        self.assertEqual(self.state.db.execute("SELECT revoked FROM grants").fetchone()[0], 1)
        self.assertEqual(self.state.meta("epoch"), 2)

    def model_worker(self):
        worker = Mock()
        worker.pending = {}
        worker.launch.side_effect = lambda action: worker.pending.update({action: object()})
        self.runtime.model_worker = worker
        self.runtime.registry.model_policy = worker.check_policy
        self.body.update(capability='model.plan', args=dict(provider='openai', model='snapshot',
            prompt='approved prompt', max_output_tokens=100), idempotency_key='model-one')
        return worker

    def test_model_approval_queues_after_reply_and_dispatches_only_once(self):
        worker = self.model_worker()
        body = self.approved()
        result = self.call('propose', body, now=12)
        worker.check_policy.assert_called_once_with(self.body['args'])
        worker.launch.assert_not_called()
        self.assertFalse(self.call('propose', body, now=12)['fresh'])
        action = result['action']['id']
        self.assertEqual(list(self.runtime.model_pending), [action])
        self.runtime.tick()
        self.runtime.tick()
        worker.launch.assert_called_once_with(action)
        worker.poll.assert_called_once_with(action)
        self.assertFalse(self.runtime.registry.leases)

    def test_disabled_model_policy_does_not_consume_approved_grant(self):
        worker = self.model_worker()
        body = self.approved()
        worker.check_policy.side_effect = Denied('disabled')
        with self.assertRaises(Denied):
            self.call('propose', body, now=12)
        self.assertEqual(self.state.db.execute('SELECT used FROM grants').fetchone()[0], 0)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 0)
        self.assertFalse(self.runtime.model_pending)
        worker.launch.assert_not_called()

    def test_failed_model_launch_is_failed_intent_without_retry(self):
        worker = self.model_worker()
        worker.launch.side_effect = OSError('listener unavailable')
        action = self.call('propose', self.approved(), now=12)['action']['id']
        self.runtime.tick()
        self.runtime.tick()
        worker.launch.assert_called_once_with(action)
        self.assertEqual(self.state.db.execute('SELECT state FROM actions WHERE id=?',
                                               (action,)).fetchone()[0], 'failed')
        self.assertFalse(self.runtime.registry.leases)

    def test_stop_before_scheduled_model_never_dispatches(self):
        worker = self.model_worker()
        self.call('propose', self.approved(), now=12)
        self.state.emergency_stop()
        self.runtime.tick()
        worker.launch.assert_not_called()
        self.assertFalse(self.runtime.model_pending)
        self.assertFalse(self.runtime.registry.leases)

    def test_close_discards_queued_model_and_marks_intent_failed(self):
        self.model_worker()
        action = self.call('propose', self.approved(), now=12)['action']['id']
        self.runtime.close()
        self.assertEqual(self.state.db.execute('SELECT state FROM actions WHERE id=?',
                                               (action,)).fetchone()[0], 'failed')
        self.assertFalse(self.runtime.model_pending)
