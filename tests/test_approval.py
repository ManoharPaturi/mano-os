import copy
import unittest

from mano_lab.approval import Request, digest


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.now = 10
        self.request = Request.create(self.now)
        self.body = {
            "action": "approve",
            "request_id": self.request.view["request_id"],
            "nonce": self.request.view["nonce"],
            "operation_digest": digest(self.request.view),
            "password": "fixture-password",
        }
        self.auth_calls = 0

    def authenticate(self, password):
        self.auth_calls += 1
        return password == "fixture-password"

    def decide(self, body=None, uid=1002):
        return self.request.decision(
            uid, 1002, self.body if body is None else body, lambda: self.now, self.authenticate
        )

    def test_kernel_identity_cannot_be_claimed_in_message(self):
        body = dict(self.body, uid=1002)
        self.assertEqual(self.decide(body, uid=1003), "peer-denied")
        self.assertEqual(self.auth_calls, 0)

    def test_target_task_nonce_and_expiry_are_bound(self):
        for field, value in [
            ("target", "/etc/mano/sentinel"),
            ("task_id", "different"),
            ("expires_at_monotonic", 999),
            ("risk", "safe"),
            ("operation", "other"),
        ]:
            altered = copy.deepcopy(self.request.view)
            altered[field] = value
            self.assertEqual(
                self.decide(dict(self.body, operation_digest=digest(altered))), "binding-denied"
            )
        self.assertEqual(self.decide(dict(self.body, nonce="different")), "binding-denied")
        self.assertEqual(self.decide(dict(self.body, target="/etc/mano/sentinel")), "schema-denied")
        self.assertEqual(self.auth_calls, 0)

    def test_wrong_password_does_not_consume_request_and_replay_is_denied(self):
        self.assertEqual(self.decide(dict(self.body, password="wrong")), "auth-denied")
        self.assertFalse(self.request.consumed)
        self.assertEqual(self.decide(), "approved")
        self.assertTrue(self.request.consumed)
        self.assertEqual(self.decide(), "replay-denied")
        self.assertEqual(self.auth_calls, 2)

    def test_expiry_rechecked_after_authentication(self):
        def delayed(_password):
            self.now = self.request.view["expires_at_monotonic"]
            return True

        self.assertEqual(
            self.request.decision(1002, 1002, self.body, lambda: self.now, delayed),
            "expired-denied",
        )
        self.assertFalse(self.request.consumed)
        self.assertEqual(self.decide(), "expired-denied")
        self.assertEqual(self.auth_calls, 0)
