import unittest
from unittest.mock import patch

from golfinho.platform.detector import detect_platform


class TestPlatformProfile(unittest.TestCase):
    @patch("golfinho.platform.detector.get_linux_info")
    @patch("golfinho.platform.detector.platform.system", return_value="Linux")
    def test_linux_profile_is_normalized(self, _system, linux_info):
        linux_info.return_value = {
            "family": "Linux", "name": "Manjaro Linux",
            "distribution": "Manjaro Linux", "distribution_id": "manjaro",
            "version": "unknown", "kernel": "6.x", "architecture": "x86_64",
            "hostname": "test-host", "is_admin": False,
        }
        result = detect_platform()
        self.assertEqual(result["family"], "Linux")
        self.assertEqual(result["distribution_id"], "manjaro")
        self.assertEqual(result["collection_mode"], "read-only")
        self.assertIn("collected_at", result)

    @patch("golfinho.platform.detector.get_windows_info")
    @patch("golfinho.platform.detector.platform.system", return_value="Windows")
    def test_windows_profile_uses_same_schema(self, _system, windows_info):
        windows_info.return_value = {
            "family": "Windows", "name": "Windows 11",
            "distribution": "Windows 11", "distribution_id": "windows",
            "version": "10.0", "kernel": "11", "architecture": "AMD64",
            "hostname": "test-host", "is_admin": False,
        }
        result = detect_platform()
        self.assertEqual(result["family"], "Windows")
        self.assertEqual(result["distribution_id"], "windows")
        self.assertEqual(result["collection_mode"], "read-only")

    @patch("golfinho.platform.detector.platform.platform", return_value="FreeBSD-14")
    @patch("golfinho.platform.detector.platform.system", return_value="FreeBSD")
    def test_unknown_platform_is_reported_without_crashing(self, _system, _platform):
        result = detect_platform()
        self.assertEqual(result["family"], "FreeBSD")
        self.assertEqual(result["distribution_id"], "unknown")
        self.assertFalse(result["is_admin"])


if __name__ == "__main__":
    unittest.main()
