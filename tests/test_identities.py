import unittest
from unittest.mock import patch

from mano_broker.identities import allocate_identity


class IdentityAllocatorGuards(unittest.TestCase):
    def test_nonroot_and_nonlinux_fail_before_lock_or_useradd(self):
        for platform, uid in (("darwin", 0), ("linux", 1004)):
            with (
                patch("mano_broker.identities.sys.platform", platform),
                patch("mano_broker.identities.os.geteuid", return_value=uid),
                patch("mano_broker.identities.os.open") as opening,
                patch("mano_broker.identities.subprocess.run") as useradd,
            ):
                with self.assertRaises(PermissionError):
                    allocate_identity()
                opening.assert_not_called()
                useradd.assert_not_called()
