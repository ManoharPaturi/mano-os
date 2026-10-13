import unittest

from mano_prompt.approve import rearm_confirmation_packet, rearm_view_packet


class NativeRearmPacketTests(unittest.TestCase):
    def setUp(self):
        self.view = dict(operation='system.rearm', generation=42, nonce='ab'*32)

    def test_bounded_packet_keeps_password_only_in_mutable_wire(self):
        self.assertEqual(rearm_view_packet(), b'\x01\x03')
        packet = rearm_confirmation_packet(self.view, 'synthetic')
        self.assertIsInstance(packet, bytearray)
        self.assertEqual(packet[:2], b'\x01\x04')
        self.assertEqual(int.from_bytes(packet[2:10], 'big'), 42)
        self.assertEqual(packet[10:74], b'ab'*32)
        self.assertEqual(int.from_bytes(packet[74:76], 'big'), 9)
        self.assertEqual(packet[76:], b'synthetic')
        packet[:] = b'\0' * len(packet)

    def test_no_unbound_or_malformed_rearm_request(self):
        for change in (dict(generation=True), dict(generation=-1), dict(generation=1 << 63),
                       dict(nonce='x'*64), dict(operation='terminal.run')):
            with self.subTest(change=change), self.assertRaises(ValueError):
                rearm_confirmation_packet(self.view | change, 'synthetic')
        for password in ('', 'x'*257, 'contains\0nul'):
            with self.assertRaises(ValueError):
                rearm_confirmation_packet(self.view, password)
