import json
import unittest
from unittest.mock import Mock, patch

from golfinho.checks.windows_firewall import (
    _normalize_bool,
    collect_windows_firewall_info,
)


class TestWindowsFirewallCollector(unittest.TestCase):
    def test_boolean_normalization(self):
        cases = [
            (True, True), (False, False), (1, True), (0, False),
            ("True", True), ("False", False), ("1", True), ("0", False),
            ("yes", True), ("no", False), ("unexpected", None), (None, None),
            (2, None),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertIs(_normalize_bool(value), expected)

    @patch("golfinho.checks.windows_firewall._run")
    def test_normalizes_profiles_rules_filters_and_service(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "profiles": [
                {"name": "Domain", "enabled": 1, "default_inbound_action": "Block",
                 "default_outbound_action": "Allow"},
                {"name": "Private", "enabled": True, "default_inbound_action": "Block",
                 "default_outbound_action": "Allow"},
            ],
            "rules": [
                {"name": "RuleA", "display_name": "Example inbound", "direction": "Inbound",
                 "action": "Allow", "profile": "Private", "policy_store_source": "Local",
                 "policy_store_source_type": "Local",
                 "port_filters": [{"Protocol": "TCP", "LocalPort": "443", "RemotePort": "Any"}],
                 "address_filters": [{"LocalAddress": "Any", "RemoteAddress": "10.0.0.0/8"}],
                 "application_filters": [{"Program": "C:\\\\app.exe", "Package": None}]},
                {"name": "RuleB", "display_name": "Example outbound", "direction": "Outbound",
                 "action": "Block", "profile": "Any", "port_filters": [],
                 "address_filters": [], "application_filters": []},
            ],
            "service": {"name": "MpsSvc", "status": "Running", "start_type": "Automatic"},
        }), stderr="")
        result = collect_windows_firewall_info()
        self.assertEqual(len(result["profiles"]), 2)
        self.assertIs(result["profiles"][0]["enabled"], True)
        self.assertIs(result["profiles"][1]["enabled"], True)
        self.assertEqual(result["rule_counts"], {"Inbound,Allow": 1, "Outbound,Block": 1})
        self.assertEqual(result["enabled_rules"][0]["port_filters"][0]["Protocol"], "TCP")
        self.assertEqual(result["enabled_rules"][0]["address_filters"][0]["RemoteAddress"], "10.0.0.0/8")
        self.assertEqual(result["enabled_rules"][0]["application_filters"][0]["Program"], "C:\\\\app.exe")
        self.assertEqual(result["service"]["status"], "Running")
        self.assertEqual(result["collection_mode"], "read-only")
        self.assertEqual(result["errors"], [])

    @patch("golfinho.checks.windows_firewall._run")
    def test_accepts_single_objects_from_powershell_json(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "profiles": {"name": "Public", "enabled": 0, "default_inbound_action": "Block",
                         "default_outbound_action": "Allow"},
            "rules": {"name": "OnlyRule", "display_name": "Only rule", "direction": "Inbound",
                      "action": "Allow", "profile": "Public"},
            "service": {"name": "MpsSvc", "status": "Running", "start_type": "Automatic"},
        }), stderr="")
        result = collect_windows_firewall_info()
        self.assertEqual(len(result["profiles"]), 1)
        self.assertIs(result["profiles"][0]["enabled"], False)
        self.assertEqual(len(result["enabled_rules"]), 1)
        self.assertEqual(result["enabled_rules"][0]["port_filters"], [])
        self.assertEqual(result["rule_counts"], {"Inbound,Allow": 1})

    @patch("golfinho.checks.windows_firewall._run")
    def test_reports_collection_failure_explicitly(self, run):
        run.return_value = Mock(returncode=1, stdout="", stderr="Access denied")
        result = collect_windows_firewall_info()
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["sources"]["profiles"]["status"], "unavailable")
        self.assertEqual(result["errors"][0]["error"], "Access denied")


if __name__ == "__main__":
    unittest.main()
