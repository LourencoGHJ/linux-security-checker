import unittest
from types import SimpleNamespace
from unittest.mock import patch

from linux_security_checker.permissions import inspect_file


class TestPermissionsAudit(unittest.TestCase):

    @patch("linux_security_checker.permissions.os.stat")
    def test_secure_public_file(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_mode=0o100644,
        )

        result = inspect_file("/etc/passwd", "PUBLIC")

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["permissions"], "0o644")

    @patch("linux_security_checker.permissions.os.stat")
    def test_detects_world_readable_shadow(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_mode=0o100644,
        )

        result = inspect_file("/etc/shadow", "SENSITIVE")

        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn(
            "Others can read sensitive file",
            result["findings"],
        )

    @patch("linux_security_checker.permissions.os.stat")
    def test_detects_group_writable_file(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_mode=0o100664,
        )

        result = inspect_file("/etc/passwd", "PUBLIC")

        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn(
            "Group has write permission",
            result["findings"],
        )

    @patch("linux_security_checker.permissions.os.stat")
    def test_detects_non_root_owner(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_uid=1000,
            st_gid=1000,
            st_mode=0o100644,
        )

        result = inspect_file("/etc/passwd", "PUBLIC")

        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn(
            "File is not owned by root",
            result["findings"],
        )

    @patch("linux_security_checker.permissions.os.stat")
    def test_missing_file(self, mock_stat):
        mock_stat.side_effect = FileNotFoundError

        result = inspect_file("/etc/ssh/sshd_config", "CONFIG")

        self.assertEqual(result["status"], "NOT_FOUND")

    @patch("linux_security_checker.permissions.os.stat")
    def test_permission_denied(self, mock_stat):
        mock_stat.side_effect = PermissionError

        result = inspect_file("/etc/shadow", "SENSITIVE")

        self.assertEqual(result["status"], "PERMISSION_DENIED")


if __name__ == "__main__":
    unittest.main()
