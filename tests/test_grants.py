import unittest

from mano_lab.approval import Request, digest, grant_decision


class GrantTests(unittest.TestCase):
    def setUp(self):
        self.request = Request.create(10)
        self.request.consumed = True
        self.body = {
            "action": "use_grant",
            "request_id": self.request.view["request_id"],
            "nonce": self.request.view["nonce"],
            "operation_digest": digest(self.request.view),
        }

    def check(self, epoch=0, latched=False, body=None):
        return grant_decision(
            self.request, self.body if body is None else body, 0, epoch, latched, lambda: 11
        )

    def test_stop_epoch_and_latch_revoke_active_authorization(self):
        self.assertEqual(self.check(), "grant-valid")
        self.assertEqual(self.check(epoch=1), "revoked-denied")
        self.assertEqual(self.check(latched=True), "revoked-denied")

    def test_scope_and_approval_cannot_be_forged(self):
        self.assertEqual(self.check(body=dict(self.body, nonce="other")), "binding-denied")
        self.assertEqual(
            self.check(body=dict(self.body, target="/etc/mano/sentinel")), "schema-denied"
        )
        self.request.consumed = False
        self.assertEqual(self.check(), "grant-denied")
