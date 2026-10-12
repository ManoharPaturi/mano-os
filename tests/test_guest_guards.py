import os
import subprocess
import unittest


class GuestGuardTests(unittest.TestCase):
    @unittest.skipIf(os.getuid() == 0, "Developer-host denial test requires unprivileged caller")
    def test_guest_mutation_scripts_reject_developer_host(self):
        for name in ("guest_lab.sh", "migrate_btrfs_root.sh", "verify_btrfs_root.sh"):
            with self.subTest(script=name):
                result = subprocess.run(
                    ["bash", "scripts/" + name],
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("Disposable Linux guest root context required", result.stderr)
