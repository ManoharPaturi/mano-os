import unittest

from mano_broker.limits import Limits
from mano_broker.state import Denied


class KernelBudgetTests(unittest.TestCase):
    def test_approved_limits_are_never_larger_than_grant_or_launcher_ceiling(self):
        for memory in (1, 64 * 1024**2, 256 * 1024**2):
            for pids in (1, 16, 32):
                for cpu in (1, 10, 100):
                    approved = dict(memory_bytes=memory, pids=pids, cpu_percent=cpu)
                    actual = Limits.approved(approved).body()
                    for key, value in actual.items():
                        self.assertLessEqual(value, approved[key])
                        self.assertLessEqual(value, Limits().body()[key])

    def test_private_limits_reject_booleans_unknown_fields_and_expansion(self):
        for value in (
            Limits().body() | {'pids': True},
            Limits().body() | {'pids': 25},
            Limits().body() | {'memory_bytes': 0},
            Limits().body() | {'cpu_percent': 21},
            Limits().body() | {'cgroup_path': '/sys/fs/cgroup'},
        ):
            with self.assertRaises(Denied):
                Limits.parse(value)
