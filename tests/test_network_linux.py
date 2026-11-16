import json
import unittest
from unittest.mock import Mock, patch

from golfinho.checks.network import _collect_linux


class TestLinuxNetworkCollector(unittest.TestCase):
    @patch("golfinho.checks.network.Path.read_text", return_value="nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
    @patch("golfinho.checks.network._run")
    def test_collects_interfaces_routes_and_dns(self, run, _resolv):
        address_data = [{"ifname": "eth0", "flags": ["BROADCAST", "UP"], "address": "00:11",
                         "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24},
                                       {"family": "inet6", "local": "2001:db8::10", "prefixlen": 64}]}]
        run.side_effect = [Mock(returncode=0, stdout=json.dumps(address_data), stderr=""),
                           Mock(returncode=0, stdout=json.dumps([{"gateway": "192.0.2.1", "dev": "eth0"}]), stderr=""),
                           Mock(returncode=0, stdout=json.dumps([{"gateway": "2001:db8::1", "dev": "eth0"}]), stderr="")]
        result = _collect_linux()
        self.assertEqual(result["interfaces"][0]["name"], "eth0")
        self.assertTrue(result["interfaces"][0]["is_up"])
        self.assertEqual(len(result["interfaces"][0]["addresses"]), 2)
        self.assertEqual(len(result["gateways"]), 2)
        self.assertEqual(result["dns_servers"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(result["errors"], [])

    @patch("golfinho.checks.network._run", side_effect=FileNotFoundError("ip"))
    @patch("golfinho.checks.network.Path.read_text", side_effect=OSError("not readable"))
    @patch("golfinho.checks.network.socket.if_nameindex", return_value=[(1, "lo")])
    def test_missing_tools_returns_partial_result(self, _names, _resolv, _run):
        result = _collect_linux()
        self.assertEqual(result["interfaces"][0]["name"], "lo")
        self.assertEqual(result["sources"]["interfaces"]["status"], "unavailable")
        self.assertEqual(result["sources"]["routes"]["status"], "unavailable")
        self.assertEqual(result["sources"]["dns"]["status"], "unavailable")
        self.assertEqual(len(result["errors"]), 3)


if __name__ == "__main__":
    unittest.main()
