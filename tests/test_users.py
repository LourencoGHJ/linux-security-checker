import unittest
from collections import namedtuple
from unittest.mock import patch

from linux_security_checker.users import check_users


Account = namedtuple(
    "Account",
    ["pw_name", "pw_uid", "pw_gid", "pw_shell"],
)

Group = namedtuple(
    "Group",
    ["gr_name", "gr_gid", "gr_mem"],
)


class TestUsersAudit(unittest.TestCase):

    @patch("linux_security_checker.users.grp.getgrall")
    @patch("linux_security_checker.users.pwd.getpwall")
    def test_detects_uid_zero_accounts(self, mock_accounts, mock_groups):
        mock_accounts.return_value = [
            Account("root", 0, 0, "/bin/bash"),
            Account("admin", 0, 0, "/bin/bash"),
            Account("guilherme", 1000, 1000, "/bin/bash"),
        ]
        mock_groups.return_value = []

        result = check_users()

        self.assertEqual(
            result["uid_zero_accounts"],
            ["admin", "root"],
        )

    @patch("linux_security_checker.users.grp.getgrall")
    @patch("linux_security_checker.users.pwd.getpwall")
    def test_detects_privileged_group_members(self, mock_accounts, mock_groups):
        mock_accounts.return_value = [
            Account("root", 0, 0, "/bin/bash"),
            Account("guilherme", 1000, 1000, "/bin/bash"),
            Account("admin", 1001, 10, "/bin/bash"),
        ]
        mock_groups.return_value = [
            Group("wheel", 10, ["guilherme"]),
        ]

        result = check_users()

        self.assertEqual(
            result["privileged_group_members"]["wheel"],
            ["admin", "guilherme"],
        )

    @patch("linux_security_checker.users.grp.getgrall")
    @patch("linux_security_checker.users.pwd.getpwall")
    def test_detects_interactive_users(self, mock_accounts, mock_groups):
        mock_accounts.return_value = [
            Account("root", 0, 0, "/bin/bash"),
            Account("guilherme", 1000, 1000, "/bin/bash"),
            Account("service", 1001, 1001, "/usr/sbin/nologin"),
            Account("disabled", 1002, 1002, "/bin/false"),
        ]
        mock_groups.return_value = []

        result = check_users()

        self.assertEqual(
            result["interactive_users"],
            ["guilherme"],
        )

    @patch("linux_security_checker.users.grp.getgrall")
    @patch("linux_security_checker.users.pwd.getpwall")
    def test_empty_system_data(self, mock_accounts, mock_groups):
        mock_accounts.return_value = []
        mock_groups.return_value = []

        result = check_users()

        self.assertEqual(result["uid_zero_accounts"], [])
        self.assertEqual(result["privileged_group_members"], {})
        self.assertEqual(result["interactive_users"], [])


if __name__ == "__main__":
    unittest.main()


class TestSystemAccounts(unittest.TestCase):

    @patch("linux_security_checker.users.grp.getgrall")
    @patch("linux_security_checker.users.pwd.getpwall")
    def test_excludes_nobody_from_interactive_users(
        self, mock_accounts, mock_groups
    ):
        mock_accounts.return_value = [
            Account("root", 0, 0, "/bin/bash"),
            Account("lourencoghj", 1000, 1000, "/bin/bash"),
            Account("nobody", 65534, 65534, "/usr/bin/nologin"),
        ]
        mock_groups.return_value = []

        result = check_users()

        self.assertEqual(
            result["interactive_users"],
            ["lourencoghj"],
        )
