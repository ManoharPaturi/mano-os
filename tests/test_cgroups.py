import unittest
from unittest.mock import patch

from mano_broker.cgroups import context
from mano_broker.state import Denied


class DelegationGuards(unittest.TestCase):
    def test_nonlinux_or_nonroot_never_reads_or_writes_cgroups(self):
        for platform, uid in (("darwin", 0), ("linux", 1004)):
            with (
                patch("mano_broker.cgroups.sys.platform", platform),
                patch("mano_broker.cgroups.os.geteuid", return_value=uid),
                patch("mano_broker.cgroups.Path.read_text") as read,
                patch("mano_broker.cgroups.os.open") as opening,
            ):
                with self.assertRaises(Denied):
                    context()
                read.assert_not_called()
                opening.assert_not_called()
