import unittest
from unittest.mock import patch

from mano_lab.processes import exited_or_zombie


class ProcessObservationTests(unittest.TestCase):
    def test_reaped_during_read_is_dead_but_live_and_permission_failure_are_not(self):
        for error in (FileNotFoundError(), ProcessLookupError()):
            with patch("mano_lab.processes.Path.read_text", side_effect=error):
                self.assertTrue(exited_or_zombie(123))
        with patch(
            "mano_lab.processes.Path.read_text", return_value="Name:\ttask\nState:\tZ (zombie)\n"
        ):
            self.assertTrue(exited_or_zombie(123))
        with patch(
            "mano_lab.processes.Path.read_text", return_value="Name:\ttask\nState:\tR (running)\n"
        ):
            self.assertFalse(exited_or_zombie(123))
        with patch("mano_lab.processes.Path.read_text", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                exited_or_zombie(123)
