import tempfile
import unittest
from pathlib import Path

from golfinho.reports.generator import generate_html_report


class TestHtmlReport(unittest.TestCase):
    def test_report_contains_system_network_firewall_and_filters(self):
        results = {
            "platform": {
                "name": "Windows 11",
                "family": "Windows",
                "version": "10.0",
                "kernel": "11",
                "architecture": "AMD64",
                "hostname": "test-host",
                "is_admin": True,
            },
            "network": {
                "interfaces": [{
                    "name": "Ethernet", "kind": "physical", "is_up": True,
                    "mac": "00-11-22-33-44-55",
                    "addresses": [{"family": "IPv4", "address": "192.0.2.10"}],
                }],
                "gateways": [{"family": "IPv4", "address": "192.0.2.1", "interface": "Ethernet"}],
                "dns_servers": ["192.0.2.53"],
                "dns_server_analysis": [{"address": "192.0.2.53", "classification": "reserved"}],
                "sources": {"interfaces": {"status": "ok"}},
            },
            "firewall": {
                "profiles": [{
                    "name": "Private", "enabled": True,
                    "default_inbound_action": "Block", "default_outbound_action": "Allow",
                }],
                "enabled_rules": [{
                    "name": "AllowHTTPS", "display_name": "HTTPS inbound",
                    "direction": "Inbound", "action": "Allow", "profile": "Private",
                    "port_filters": [{"Protocol": "TCP", "LocalPort": "443"}],
                    "address_filters": [{"RemoteAddress": "10.0.0.0/8"}],
                    "application_filters": [{"Program": "C:\\\\app.exe"}],
                }],
                "rule_counts": {"Inbound,Allow": 1},
                "service": {"name": "MpsSvc", "status": "Running", "start_type": "Automatic"},
                "sources": {"profiles": {"status": "ok"}},
            },
            "findings": [],
            "errors": [],
            "checks_skipped": [{"check": "users", "reason": "NOT_IMPLEMENTED_FOR_PLATFORM"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            report = generate_html_report(results, output_dir=directory)
            html = Path(report).read_text(encoding="utf-8")

        for expected in (
            "Inventário de rede", "Windows Firewall", "Ethernet", "192.0.2.1",
            "HTTPS inbound", "TCP", "443", "10.0.0.0/8", "MpsSvc",
            "Verificações não implementadas", "golfinho-mascot.jpg",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)


if __name__ == "__main__":
    unittest.main()
