import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import administration as admin


class RuntimeAdministrationTests(unittest.TestCase):
    def accounts(self):
        return [
            SimpleNamespace(
                pw_name=name,
                pw_uid=100 + i,
                pw_gid=200 + i,
                pw_dir="/nonexistent",
                pw_shell="/usr/sbin/nologin",
            )
            for i, name in enumerate(("mano-broker", "mano-provider", "mano-egress"))
        ]

    def validate(self, accounts):
        names = {account.pw_name: account for account in accounts}
        groups = {
            account.pw_gid: SimpleNamespace(gr_name=account.pw_name, gr_mem=[])
            for account in accounts
        }
        with (
            patch.object(admin.pwd, "getpwall", return_value=accounts),
            patch.object(admin.pwd, "getpwnam", side_effect=names.__getitem__),
            patch.object(admin.grp, "getgrgid", side_effect=groups.__getitem__),
            patch.object(admin.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=333)),
            patch.object(admin.os, "getgrouplist", side_effect=lambda _name, gid: [gid]),
            patch.object(
                admin,
                "command",
                side_effect=lambda *args: SimpleNamespace(stdout=args[-1] + " L synthetic"),
            ),
        ):
            admin.validate_accounts()

    def test_private_locked_service_accounts_are_accepted(self):
        self.validate(self.accounts())

    def test_shared_service_uid_is_rejected(self):
        accounts = self.accounts()
        accounts[1].pw_uid = accounts[0].pw_uid
        with self.assertRaises(ValueError):
            self.validate(accounts)

    def test_existing_login_account_is_never_repurposed_as_service(self):
        accounts = self.accounts()
        accounts[0].pw_shell = "/bin/bash"
        with self.assertRaises(ValueError):
            self.validate(accounts)

    def test_human_must_be_existing_nonservice_login(self):
        for name, uid, shell in (
            ("root", 0, "/bin/bash"),
            ("mano-agent", 1001, "/bin/bash"),
            ("locked-service", 1002, "/usr/sbin/nologin"),
        ):
            account = SimpleNamespace(pw_name=name, pw_uid=uid, pw_shell=shell)
            with patch.object(admin.pwd, "getpwnam", return_value=account):
                with self.assertRaises(ValueError):
                    admin.human_account(name)
        account = SimpleNamespace(pw_name="human", pw_uid=1000, pw_shell="/bin/bash")
        with patch.object(admin.pwd, "getpwnam", return_value=account):
            self.assertIs(admin.human_account("human"), account)

    def test_package_preflight_rejects_existing_unsafe_account_before_sysusers(self):
        with (
            patch.object(admin, "root"),
            patch.object(admin, "validate_accounts", side_effect=ValueError("unsafe existing")),
            patch.object(admin, "command") as command,
        ):
            with self.assertRaises(ValueError):
                admin.configure_package()
            command.assert_not_called()

    def test_enrollment_without_tty_performs_no_mutation(self):
        with (
            patch.object(admin, "root"),
            patch.object(admin.os, "isatty", return_value=False),
            patch.object(admin, "command") as command,
        ):
            with self.assertRaises(ValueError):
                admin.enroll("human", start=True)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
