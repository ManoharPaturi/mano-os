import importlib.util
import json
import unittest


class SerialFrameTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("serial_rescue", "scripts/serial_rescue.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_uart_fragments_require_complete_response(self):
        response = json.dumps(
            {"challenge": "fixture-token", "uid": 1002, "tty": "/dev/ttyS0"}
        ).encode()
        for length in range(len(response)):
            self.assertEqual(self.module.challenge_values(response[:length], "fixture-token"), [])
        self.assertEqual(
            self.module.challenge_values(response, "fixture-token")[0]["tty"], "/dev/ttyS0"
        )

    def test_wrong_challenge_and_echo_are_not_responses(self):
        for response in (
            b"python3 -c print(fixture-token)",
            b'{"challenge":"different"}',
            b"fixture-token\r\nlogin: ",
        ):
            self.assertEqual(self.module.challenge_values(response, "fixture-token"), [])
