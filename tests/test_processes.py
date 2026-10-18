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

    def test_dead_transition_is_exited_but_live_or_unknown_state_is_not(self):
        for state in ('Z (zombie)', 'X (dead)'):
            with self.subTest(state=state), patch(
                'mano_lab.processes.Path.read_text', return_value='State:\t' + state + '\n'
            ):
                self.assertTrue(exited_or_zombie(123))
        for state in ('R (running)', 'S (sleeping)', 'D (disk sleep)', 'T (stopped)', '', 'Q'):
            with self.subTest(state=state), patch(
                'mano_lab.processes.Path.read_text', return_value='State:\t' + state + '\n'
            ):
                self.assertFalse(exited_or_zombie(123))
        with patch('mano_lab.processes.Path.read_text', return_value='Name:\ttask\n'):
            self.assertFalse(exited_or_zombie(123))
