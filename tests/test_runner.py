import unittest
from unittest.mock import patch

from mano_broker.runner import run


class RunnerAdmissionGuards(unittest.TestCase):
    def test_invalid_budget_never_launches(self):
        for deadline in (True, 0, 301, 1.5):
            with patch("mano_broker.runner.subprocess.Popen") as launch:
                with self.assertRaises(ValueError):
                    run(3, 4, ["true"], timeout=deadline, revoked=lambda: False)
                launch.assert_not_called()

    def test_revoked_or_invalid_observer_never_launches(self):
        with patch("mano_broker.runner.subprocess.Popen") as launch:
            result = run(3, 4, ["true"], timeout=1, revoked=lambda: True)
            self.assertEqual(result.reason, "revoked")
            self.assertIsNone(result.return_code)
            with self.assertRaises(ValueError):
                run(3, 4, ["true"], timeout=1, revoked=lambda: "false")
            launch.assert_not_called()
