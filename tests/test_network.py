import json
import unittest
from unittest.mock import Mock, patch

from golfinho.checks.network import _collect_windows, collect_network_info


class TestNetworkCollector(unittest.TestCase):
    @patch("golfinho.checks.network.platform.system", return_value="FreeBSD")
    def test_unknown_platform_reports_unsupported_sources(self, _system):
        result = collect_network_info()
        self.assertEqual(result["collection_mode"], "read-only")
        self.assertEqual(result["sources"]["interfaces"]["status"], "unsupported")

    @patch("golfinho.checks.network._collect_linux")
    @patch("golfinho.checks.network.platform.system", return_value="Linux")
    def test_linux_dispatch(self, _system, collector):
        collector.return_value = {"platform": "Linux"}
        self.assertEqual(collect_network_info(), {"platform": "Linux"})
        collector.assert_called_once_with()

    @patch("golfinho.checks.network._run")
    def test_windows_normalizes_network_data(self, run):
        payload = {"interfaces": [{"name": "Ethernet", "status": "Up", "mac": "00-11", "if_index": 7}],
                   "addresses": [{"interface_index": 7, "family": "IPv4", "address": "192.0.2.10", "prefix_length": 24}],
                   "routes": [{"family": "IPv4", "address": "192.0.2.1", "interface_index": 7}],
                   "dns": [{"interface_index": 7, "address": "192.0.2.53"}]}
        run.return_value = Mock(returncode=0, stdout=json.dumps(payload), stderr="")
        result = _collect_windows()
        self.assertEqual(result["interfaces"][0]["name"], "Ethernet")
        self.assertTrue(result["interfaces"][0]["is_up"])
        self.assertEqual(result["interfaces"][0]["addresses"][0]["prefix_length"], 24)
        self.assertEqual(result["gateways"][0]["address"], "192.0.2.1")
        self.assertEqual(result["dns_servers"], ["192.0.2.53"])
        self.assertEqual(result["errors"], [])

    @patch("golfinho.checks.network._run", side_effect=FileNotFoundError("powershell.exe"))
    def test_windows_failure_is_explicit(self, _run):
        result = _collect_windows()
        self.assertTrue(result["errors"])
        self.assertEqual(result["sources"]["interfaces"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
