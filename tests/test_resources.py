import unittest

from mano_lab.resources import memory_counters, process_memory


class ResourceCounterTests(unittest.TestCase):
    def test_units_and_unknown_fields(self):
        values = memory_counters(
            "MemTotal: 1024 kB\nVmRSS: 512 kB\nThreads: 8\nMalformed\nBad: x kB\n"
        )
        self.assertEqual(values, {"MemTotal": 1048576, "VmRSS": 524288})

    def test_invalid_pid_is_rejected_before_file_access(self):
        for pid in (0, -1):
            with self.assertRaises(ValueError):
                process_memory(pid)
