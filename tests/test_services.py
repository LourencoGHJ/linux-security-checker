import subprocess
import unittest
from unittest.mock import patch

from linux_security_checker.services import (
    check_services,
    parse_service_units,
)


class TestServiceParsing(unittest.TestCase):

    def test_parses_service_names(self):
        output = (
            "sshd.service loaded active running OpenSSH server\n"
            "ufw.service loaded active running Uncomplicated Firewall\n"
        )

        self.assertEqual(
            parse_service_units(output),
            ["sshd.service", "ufw.service"],
        )

    def test_ignores_empty_output(self):
        self.assertEqual(parse_service_units(""), [])


class TestServicesAudit(unittest.TestCase):

    @patch("linux_security_checker.services.shutil.which")
    def test_systemd_unavailable(self, mock_which):
        mock_which.return_value = None

        result = check_services()

        self.assertEqual(result["status"], "SYSTEMD_UNAVAILABLE")
        self.assertEqual(result["running_services"], [])

    @patch("linux_security_checker.services.run_systemctl")
    @patch("linux_security_checker.services.shutil.which")
    def test_detects_services(self, mock_which, mock_command):
        mock_which.return_value = "/usr/bin/systemctl"

        mock_command.side_effect = [
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="sshd.service loaded active running OpenSSH\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="sshd.service enabled enabled\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ]

        result = check_services()

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["running_services"], ["sshd.service"])
        self.assertEqual(result["enabled_services"], ["sshd.service"])
        self.assertEqual(result["failed_services"], [])

    @patch("linux_security_checker.services.run_systemctl")
    @patch("linux_security_checker.services.shutil.which")
    def test_partial_result_on_command_failure(
        self, mock_which, mock_command
    ):
        mock_which.return_value = "/usr/bin/systemctl"

        mock_command.side_effect = [
            None,
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="sshd.service enabled enabled\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ]

        result = check_services()

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["running_services"], [])
        self.assertEqual(result["enabled_services"], ["sshd.service"])


if __name__ == "__main__":
    unittest.main()
