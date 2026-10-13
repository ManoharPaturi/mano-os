import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State


class ApprovalQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve() / "broker"
        self.state = State(self.directory)
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id="a" * 32,
            classification="sensitive",
            boot_id="boot-a",
        )
        self.queue = Approvals(self.state)
        self.proposal = dict(
            schema_version="1.0",
            task_id=self.task,
            capability="files.write",
            resource_id="a" * 32,
            args={"path": "result", "text": "approved"},
            idempotency_key="write",
            reason="model explanation, not authority",
        )

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def request(self, **changes):
        return self.queue.request(
            self.proposal | changes, caller_uid=1004, now=10, boot_id="boot-a"
        )

    def confirmation(self, approval_id):
        view = self.queue.view(approval_id, human_uid=1002)
        return dict(
            authenticated_human_uid=1002,
            nonce=view["nonce"],
            operation_digest=view["operation_digest"],
            now=11,
            boot_id="boot-a",
        )

    def test_private_challenge_and_exact_single_use_grant(self):
        request = self.request()
        aid = request["approval_id"]
        self.assertEqual(set(request), {"approval_id", "state", "grant_id"})
        self.assertIsNone(request["grant_id"])
        self.assertEqual(self.request(), request)
        grant = self.queue.approve(aid, **self.confirmation(aid))
        self.assertEqual(
            self.queue.status(aid, caller_uid=1004, now=12, boot_id="boot-a")["grant_id"], grant
        )
        packet = ActionRequest.parse(canonical(self.proposal | {"grant_id": grant}).encode())
        self.assertTrue(self.state.authorize(packet, caller_uid=1004, now=12, boot_id="boot-a")[1])
        with self.assertRaises(Denied):
            self.queue.approve(aid, **self.confirmation(aid))
        altered = ActionRequest.parse(
            canonical(
                self.proposal
                | {
                    "grant_id": grant,
                    "args": {"path": "other", "text": "approved"},
                    "idempotency_key": "changed",
                }
            ).encode()
        )
        with self.assertRaises(Denied):
            self.state.authorize(altered, caller_uid=1004, now=12, boot_id="boot-a")

    def test_wrong_human_nonce_digest_expiry_boot_and_stop_fail_closed(self):
        aid = self.request()["approval_id"]
        confirmed = self.confirmation(aid)
        for change in (
            {"authenticated_human_uid": 1004},
            {"authenticated_human_uid": True},
            {"nonce": "0" * 64},
            {"operation_digest": "0" * 64},
            {"now": 70},
            {"boot_id": "boot-b"},
        ):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.queue.approve(aid, **(confirmed | change))
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], 0)
        self.state.emergency_stop()
        with self.assertRaises(Denied):
            self.queue.approve(aid, **confirmed)

    def test_caller_status_and_conflicting_replay_are_denied(self):
        aid = self.request()["approval_id"]
        with self.assertRaises(Denied):
            self.request(args={"path": "other", "text": "approved"})
        for uid, boot in ((1001, "boot-a"), (1004, "boot-b")):
            with self.assertRaises(Denied):
                self.queue.status(aid, caller_uid=uid, now=12, boot_id=boot)
        with self.assertRaises(Denied):
            self.queue.view(aid, human_uid=1001)
        with self.assertRaises(Denied):
            self.queue.request(self.proposal, caller_uid=1001, now=10, boot_id="boot-a")
        with self.assertRaises(Denied):
            self.request(resource_id="b" * 32)
        with self.assertRaises(Denied):
            self.request(approved=True)

    def test_restart_preserves_challenge_but_not_permission_to_self_approve(self):
        aid = self.request()["approval_id"]
        confirmation = self.confirmation(aid)
        self.state.close()
        self.state = State(self.directory)
        self.queue = Approvals(self.state)
        self.assertEqual(self.confirmation(aid), confirmation)
        self.assertIsNone(
            self.queue.status(aid, caller_uid=1004, now=12, boot_id="boot-a")["grant_id"]
        )
        self.queue.approve(aid, **confirmation)

    def test_grant_failure_rolls_back_consumption_and_inserted_grant(self):
        aid = self.request()["approval_id"]
        issue = self.state.issue_grant

        def failing(*args, **kwargs):
            issue(*args, **kwargs)
            raise RuntimeError("simulated failure after grant insert")

        with (
            patch.object(self.state, "issue_grant", side_effect=failing),
            self.assertRaises(RuntimeError),
        ):
            self.queue.approve(aid, **self.confirmation(aid))
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], 0)
        self.assertEqual(
            self.queue.status(aid, caller_uid=1004, now=12, boot_id="boot-a")["state"], "pending"
        )
        self.queue.approve(aid, **self.confirmation(aid))

    def test_two_connections_cannot_consume_the_same_challenge(self):
        aid = self.request()["approval_id"]
        confirmation = self.confirmation(aid)
        barrier = Barrier(2)

        def consume(_):
            state = State(self.directory)
            queue = Approvals(state)
            try:
                barrier.wait(timeout=5)
                queue.approve(aid, **confirmation)
                return True
            except Denied:
                return False
            finally:
                state.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(consume, (1, 2))), 1)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], 1)

    def test_lifetime_quota_cannot_be_reset_by_waiting_for_expiry(self):
        for index in range(64):
            self.request(idempotency_key=f"request-{index}")
        with self.assertRaises(Denied):
            self.queue.request(
                self.proposal | {"idempotency_key": "overflow"},
                caller_uid=1004,
                now=10000,
                boot_id="boot-a",
            )

    def test_public_status_reports_expiry_and_revocation_without_exposing_view(self):
        aid = self.request()["approval_id"]
        status = self.queue.status(aid, caller_uid=1004, now=70, boot_id="boot-a")
        self.assertEqual(status["state"], "expired")
        self.assertEqual(set(status), {"approval_id", "state", "grant_id"})
        self.state.emergency_stop()
        self.assertEqual(
            self.queue.status(aid, caller_uid=1004, now=12, boot_id="boot-a")["state"], "revoked"
        )
