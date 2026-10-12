import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_prompt.requests import store_request


class PromptRequestTests(unittest.TestCase):
    def test_command_like_input_stays_literal_data(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("pathlib.Path.home", return_value=Path(directory)),
        ):
            text = "$(touch /tmp/should-not-exist); sudo reboot"
            message = store_request(text)
            path = Path(directory) / ".local/state/mano/requests.jsonl"
            self.assertEqual(json.loads(path.read_text()), message)
            self.assertEqual(message["text"], text)
            self.assertEqual(message["kind"], "prompt_request")
            self.assertEqual(message["uid"], os.getuid())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn("grant", message)

    def test_invalid_input_creates_no_receipt(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("pathlib.Path.home", return_value=Path(directory)),
        ):
            for text in ("", "   ", "\x00", "x" * 8193):
                with self.assertRaises(ValueError):
                    store_request(text)
            self.assertFalse((Path(directory) / ".local").exists())

    def test_receipt_symlink_is_rejected(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("pathlib.Path.home", return_value=Path(directory)),
        ):
            root = Path(directory)
            target = root / "preserve"
            target.write_text("unchanged")
            folder = root / ".local/state/mano"
            folder.mkdir(parents=True)
            (folder / "requests.jsonl").symlink_to(target)
            with self.assertRaises(OSError):
                store_request("Show system status")
            self.assertEqual(target.read_text(), "unchanged")
