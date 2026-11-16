import json
import unittest
from unittest.mock import Mock, patch

from golfinho.checks.windows_firewall import collect_windows_firewall_info


class TestWindowsFirewallCollector(unittest.TestCase):
    @patch("golfinho.checks.windows_firewall._run")
    def test_normalizes_profiles_rules_and_service(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "profiles": [
                {"name": "Domain", "enabled": True, "default_inbound_action": "Block",
                 "default_outbound_action": "Allow"},
                {"name": "Private", "enabled": True, "default_inbound_action": "Block",
                 "default_outbound_action": "Allow"},
            ],
            "rules": [
                {"name": "RuleA", "display_name": "Example inbound", "direction": "Inbound",
                 "action": "Allow", "profile": "Private", "policy_store_source": "Local",
                 "policy_store_source_type": "Local"},
                {"name": "RuleB", "display_name": "Example outbound", "direction": "Outbound",
                 "action": "Block", "profile": "Any", "policy_store_source": "Local",
                 "policy_store_source_type": "Local"},
            ],
            "service": {"name": "MpsSvc", "status": "Running", "start_type": "Automatic"},
        }), stderr="")
        result = collect_windows_firewall_info()
        self.assertEqual(len(result["profiles"]), 2)
        self.assertEqual(result["profiles"][0]["default_inbound_action"], "Block")
        self.assertEqual(result["rule_counts"], {"Inbound,Allow": 1, "Outbound,Block": 1})
        self.assertEqual(result["service"]["status"], "Running")
        self.assertEqual(result["collection_mode"], "read-only")
        self.assertEqual(result["errors"], [])

    @patch("golfinho.checks.windows_firewall._run")
    def test_accepts_single_objects_from_powershell_json(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "profiles": {"name": "Public", "enabled": True, "default_inbound_action": "Block",
                         "default_outbound_action": "Allow"},
            "rules": {"name": "OnlyRule", "display_name": "Only rule", "direction": "Inbound",
                      "action": "Allow", "profile": "Public"},
            "service": {"name": "MpsSvc", "status": "Running", "start_type": "Automatic"},
        }), stderr="")
        result = collect_windows_firewall_info()
        self.assertEqual(len(result["profiles"]), 1)
        self.assertEqual(len(result["enabled_rules"]), 1)
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
