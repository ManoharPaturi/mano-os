import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.delegate_home import Home, validate_antigravity_settings
from mano_core.delegates import CodingDelegate, classify, proposal
from mano_protocol.delegates import EXECUTABLES, command, identify


class DelegateContracts(unittest.TestCase):
    def test_fixed_commands_cannot_accept_bypass_config_or_unbounded_prompt(self):
        for name in EXECUTABLES:
            argv = command(name, "run", prompt="Fix the project", model="explicit-model")
            self.assertEqual(identify(argv), name)
            for flag in ("--yolo", "--dangerously-skip-permissions", "--config=/tmp/evil"):
                with self.assertRaises(ValueError):
                    identify(argv + [flag])
            with self.assertRaises(ValueError):
                command(name, "run", prompt="x" * 2049, model="explicit-model")
        for name in EXECUTABLES:
            args = command(name, "run", prompt="--yolo", model="--dangerous-looking-value")
            self.assertEqual(identify(args), name)
            self.assertNotIn("--yolo", args[:-1])
            self.assertIn("--model=--dangerous-looking-value", args)
        value = proposal(
            delegate="antigravity",
            operation="version",
            task_id="a" * 32,
            resource_id="b" * 32,
            key="inspect",
            reason="Inspect pinned CLI",
        )
        self.assertEqual(value["capability"], "terminal.open_pty")
        self.assertNotIn("grant_id", value)
        self.assertNotIn("env", value["args"])

    def test_antigravity_settings_rejected_before_any_vendor_launch(self):
        for value in (
            b"{invalid-json",
            b"[]",
            b"{}",
            b'{"agentMode":"default","agentMode":"plan","permissions":{"allow":[]}}',
            b'{"agentMode":"default","permissions":{"allow":["command(*)"]}}',
        ):
            with self.assertRaises(ValueError):
                validate_antigravity_settings(value)
        validate_antigravity_settings(
            b'{"agentMode":"default","permissions":{"allow":[]},"modelProvider":"gemini"}'
        )

    def test_soft_denied_exit_zero_is_not_completed(self):
        data = b'{"event":"result","result":{"status":"SUCCESS"}}\n'
        outcome = dict(reason="exited", return_code=0)
        for message in (
            b"Tool run_command requires approval\n",
            b"soft-denied: run_command\n",
            b"permission denied\n",
        ):
            result = classify("antigravity", "run", data + message, outcome)
            self.assertEqual(result["status"], "denied")
            self.assertFalse(result["effect_verified"])

    def test_json_success_is_unverified_and_partial_or_duplicate_results_are_unknown(self):
        outcome = dict(reason="exited", return_code=0)
        for name, data in (
            ("antigravity", b'{"event":"result","result":{"status":"SUCCESS"}}'),
            ("codex", b'{"type":"turn.completed"}'),
        ):
            result = classify(name, "run", data, outcome)
            self.assertEqual(result["status"], "completed-unverified")
            self.assertFalse(result["effect_verified"])
            self.assertEqual(
                classify(name, "run", data + b"\n" + data, outcome)["status"], "unknown"
            )
            self.assertEqual(classify(name, "run", data[:-1], outcome)["status"], "unknown")
            self.assertEqual(
                classify(name, "run", data, outcome | dict(reason="closed"))["status"], "unknown"
            )
            self.assertEqual(
                classify(name, "run", data + b"\nunparsed warning", outcome)["status"], "unknown"
            )

    def test_authentication_denial_and_errors_are_explicit(self):
        self.assertEqual(
            classify(
                "codex", "run", b"No credentials available", dict(reason="exited", return_code=1)
            )["status"],
            "denied",
        )
        self.assertEqual(
            classify(
                "codex", "run", b'{"type":"turn.failed"}', dict(reason="exited", return_code=0)
            )["status"],
            "failed",
        )
        self.assertEqual(
            classify(
                "codex", "version", b"codex-cli unexpected", dict(reason="exited", return_code=0)
            )["status"],
            "failed",
        )

    def test_stream_keeps_partial_lines_and_never_executes_event_text(self):
        chunks = [b'{"type":"turn.', b'completed"}\n']
        session = SimpleNamespace(output=bytearray())

        def read():
            data = chunks.pop(0)
            session.output.extend(data)
            return dict(
                data=data,
                eof=not chunks,
                state="done" if not chunks else "executing",
                outcome=dict(reason="exited", return_code=0) if not chunks else None,
            )

        session.read = read
        worker = CodingDelegate(session, name="codex", operation="run")
        worker.started = True
        self.assertEqual(worker.read()["events"], [])
        with self.assertRaises(ValueError):
            worker.result()
        events = worker.read()["events"]
        self.assertTrue(events[0]["untrusted"])
        self.assertEqual(events[0]["value"], {"type": "turn.completed"})
        self.assertEqual(worker.result()["status"], "completed-unverified")

    @unittest.skipUnless(sys.platform == "linux", "Linux sealed configuration required")
    def test_home_config_is_sealed_and_parent_home_readonly_with_bounded_volatile_mounts(self):
        import fcntl
        import os

        with patch("mano_broker.delegate_home.installed"):
            for name in EXECUTABLES:
                with Home(command(name, "version")) as home:
                    for descriptor in home.descriptors:
                        with self.assertRaises(OSError):
                            os.write(descriptor, b"override")
                        self.assertFalse(os.get_inheritable(descriptor))
                    if name == "antigravity":
                        import uuid

                        self.assertEqual(len(home.descriptors), 3)
                        seed = os.pread(home.seed_fd, 64, 0).decode()
                        self.assertEqual(str(uuid.UUID(seed)), seed)
                    fragment = home.fragment()
                    index = fragment.index("--remount-ro")
                    self.assertEqual(fragment[index + 1], "/home/task")
                    self.assertNotIn("--share-net", fragment)
                    self.assertFalse(os.get_inheritable(home.fd))
                    self.assertTrue(fcntl.fcntl(home.fd, fcntl.F_GET_SEALS))
                    if name == "antigravity":
                        data = os.pread(home.fd, 4096, 0)
                        self.assertEqual(json.loads(data)["permissions"]["allow"], [])
                self.assertEqual(home.fd, -1)
