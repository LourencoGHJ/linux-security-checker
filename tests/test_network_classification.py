import unittest
from unittest.mock import patch

from golfinho.checks.network import (
    _classify_dns_server,
    _linux_interface_kind,
)


class TestNetworkClassification(unittest.TestCase):
    def test_dns_addresses_are_classified_without_reachability_claims(self):
        self.assertEqual(_classify_dns_server("192.168.1.1"), "private")
        self.assertEqual(_classify_dns_server("1.1.1.1"), "global")
        self.assertEqual(_classify_dns_server("127.0.0.1"), "loopback")
        self.assertEqual(_classify_dns_server("169.254.1.1"), "link_local")
        self.assertEqual(_classify_dns_server("fec0:0:0:ffff::1"), "deprecated_site_local")
        self.assertEqual(_classify_dns_server("not-an-ip"), "invalid")

    def test_loopback_is_classified_by_name_or_link_type(self):
        self.assertEqual(_linux_interface_kind("lo"), "loopback")
        self.assertEqual(_linux_interface_kind("if-test", "loopback"), "loopback")

    @patch("golfinho.checks.network.Path.exists", side_effect=[True, False])
    def test_linux_virtual_interface_is_classified(self, _exists):
        self.assertEqual(_linux_interface_kind("docker0"), "virtual")

    @patch("golfinho.checks.network.Path.exists", side_effect=[False, True])
    def test_linux_hardware_interface_is_classified(self, _exists):
        self.assertEqual(_linux_interface_kind("enp3s0"), "physical")


if __name__ == "__main__":
    unittest.main()
