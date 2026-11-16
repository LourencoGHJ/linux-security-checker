import unittest
from unittest.mock import patch

from golfinho.engine.scanner import run_security_scan


class TestCrossPlatformScanner(unittest.TestCase):
    @patch("golfinho.checks.network.collect_network_info")
    @patch("golfinho.platform.detector.detect_platform")
    def test_windows_scan_skips_linux_only_checks(self, detect, network):
        detect.return_value = {"family": "Windows", "name": "Windows 11"}
        network.return_value = {"platform": "Windows", "interfaces": [], "gateways": [],
                                "dns_servers": [], "sources": {}, "errors": [],
                                "collection_mode": "read-only"}

        result = run_security_scan()

        self.assertEqual(result["platform"]["family"], "Windows")
        self.assertEqual(result["network"]["platform"], "Windows")
        network.assert_called_once_with()
        self.assertIsNone(result["firewall"])
        self.assertIsNone(result["users"])
        self.assertIsNone(result["services"])
        self.assertIsNone(result["permissions"])
        self.assertEqual(len(result["checks_skipped"]), 4)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["errors"], [])

    @patch("golfinho.engine.scanner._load_linux_checks")
    @patch("golfinho.checks.network.collect_network_info")
    @patch("golfinho.platform.detector.detect_platform")
    def test_linux_scan_loads_linux_checks(self, detect, network, load_checks):
        detect.return_value = {"family": "Linux", "name": "Manjaro"}
        network.return_value = {"platform": "Linux", "interfaces": [], "gateways": [],
                                "dns_servers": [], "sources": {}, "errors": [],
                                "collection_mode": "read-only"}
        load_checks.return_value = {
            "firewall": lambda: {"ufw": "NOT_INSTALLED"},
            "users": lambda: {},
            "services": lambda: {"failed_services": []},
            "permissions": lambda: [],
        }

        result = run_security_scan()

        load_checks.assert_called_once_with()
        self.assertEqual(result["checks_skipped"], [])
        self.assertEqual(result["network"]["platform"], "Linux")
        network.assert_called_once_with()
        self.assertEqual(result["firewall"], {"ufw": "NOT_INSTALLED"})
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
