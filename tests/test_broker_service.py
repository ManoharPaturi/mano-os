import unittest

from mano_broker.service import Admission


class AdmissionTests(unittest.TestCase):
    def test_burst_exhaustion_refill_and_idle_cap(self):
        budget = Admission(10)
        self.assertTrue(all(budget.admit(10) for _ in range(20)))
        self.assertFalse(budget.admit(10))
        self.assertFalse(budget.admit(10.01))
        self.assertTrue(budget.admit(10.2))
        self.assertTrue(all(budget.admit(100) for _ in range(20)))
        self.assertFalse(budget.admit(100))
