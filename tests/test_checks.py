import subprocess
import unittest
from unittest.mock import patch

from linux_security_checker import checks


class TestFirewallChecks(unittest.TestCase):

    @patch("linux_security_checker.checks.run_command")
    @patch("linux_security_checker.checks.shutil.which")
    def test_ufw_active(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/ufw"
        mock_command.return_value = subprocess.CompletedProcess(
            args=["ufw", "status"],
            returncode=0,
            stdout="Status: active",
            stderr="",
        )

        self.assertEqual(checks.check_ufw(), "ACTIVE")

    @patch("linux_security_checker.checks.run_command")
    @patch("linux_security_checker.checks.shutil.which")
    def test_ufw_inactive(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/ufw"
        mock_command.return_value = subprocess.CompletedProcess(
            args=["ufw", "status"],
            returncode=0,
            stdout="Status: inactive",
            stderr="",
        )

        self.assertEqual(checks.check_ufw(), "INACTIVE")

    @patch("linux_security_checker.checks.shutil.which")
    def test_ufw_not_installed(self, mock_which):
        mock_which.return_value = None

        self.assertEqual(checks.check_ufw(), "NOT_INSTALLED")

    @patch("linux_security_checker.checks.run_command")
    @patch("linux_security_checker.checks.shutil.which")
    def test_ufw_permission_denied(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/ufw"
        mock_command.return_value = subprocess.CompletedProcess(
            args=["ufw", "status"],
            returncode=1,
            stdout="",
            stderr="ERROR: You need to be root to run this script",
        )

        self.assertEqual(checks.check_ufw(), "PERMISSION_DENIED")

    @patch("linux_security_checker.checks.run_command")
    @patch("linux_security_checker.checks.shutil.which")
    def test_nftables_empty_ruleset(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/nft"
        mock_command.return_value = subprocess.CompletedProcess(
            args=["nft", "list", "ruleset"],
            returncode=0,
            stdout="",
            stderr="",
        )

        self.assertEqual(checks.check_nftables(), "EMPTY_RULESET")

    @patch("linux_security_checker.checks.run_command")
    @patch("linux_security_checker.checks.shutil.which")
    def test_nftables_iptables_backend(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/nft"
        mock_command.return_value = subprocess.CompletedProcess(
            args=["nft", "list", "ruleset"],
            returncode=0,
            stdout="table ip filter {\n}\n",
            stderr="# Warning: table ip filter is managed by iptables-nft",
        )

        self.assertEqual(
            checks.check_nftables(),
            "RULESET_PRESENT_IPTABLES_NFT",
        )

    @patch("linux_security_checker.checks.run_command")
    @patch("linux_security_checker.checks.shutil.which")
    def test_nftables_permission_denied(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/nft"
        mock_command.return_value = subprocess.CompletedProcess(
            args=["nft", "list", "ruleset"],
            returncode=1,
            stdout="",
            stderr="Operation not permitted",
        )

        self.assertEqual(checks.check_nftables(), "PERMISSION_DENIED")


if __name__ == "__main__":
    unittest.main()
