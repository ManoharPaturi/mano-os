import unittest

from mano_prompt.approve import confirmation_packet, view_packet


class ApprovalPacketTests(unittest.TestCase):
    def setUp(self):
        self.view = dict(approval_id="a" * 32, nonce="b" * 64, operation_digest="c" * 64)

    def test_native_binary_layout_uses_utf8_byte_length(self):
        self.assertEqual(view_packet("a" * 32), b"\x01\x01" + b"a" * 32)
        packet = confirmation_packet(self.view, "é")
        self.assertEqual(packet[:2], b"\x01\x02")
        self.assertEqual(packet[2:34], b"a" * 32)
        self.assertEqual(packet[34:98], b"b" * 64)
        self.assertEqual(packet[98:162], b"c" * 64)
        self.assertEqual(packet[162:164], b"\x00\x02")
        self.assertEqual(packet[164:], "é".encode())

    def test_invalid_ids_challenges_and_passwords_are_not_serialized(self):
        with self.assertRaises(ValueError):
            view_packet("../etc")
        for update in (
            {"nonce": "z" * 64},
            {"operation_digest": "c" * 65},
            {"approval_id": "a" * 31},
        ):
            with self.assertRaises(ValueError):
                confirmation_packet(self.view | update, "test")
        for password in ("", "a" * 257, "a\0b"):
            with self.assertRaises(ValueError):
                confirmation_packet(self.view, password)
