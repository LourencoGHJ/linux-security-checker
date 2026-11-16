"""Read-only Windows Defender Firewall inventory."""
import json
import subprocess


_WINDOWS_FIREWALL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object @{Name='name';Expression={$_.Name.ToString()}}, @{Name='enabled';Expression={[bool]$_.Enabled}}, @{Name='default_inbound_action';Expression={$_.DefaultInboundAction.ToString()}}, @{Name='default_outbound_action';Expression={$_.DefaultOutboundAction.ToString()}})
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)
$ruleData = @(
    foreach ($rule in $rules) {
        $port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule | Select-Object Protocol, LocalPort, RemotePort, IcmpType, DynamicTarget)
        $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule | Select-Object LocalAddress, RemoteAddress)
        $application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule | Select-Object Program, Package)
        [pscustomobject]@{
            name = $rule.Name
            display_name = $rule.DisplayName
            direction = $rule.Direction.ToString()
            action = $rule.Action.ToString()
            profile = $rule.Profile.ToString()
            policy_store_source = $rule.PolicyStoreSource
            policy_store_source_type = $rule.PolicyStoreSourceType.ToString()
            port_filters = $port
            address_filters = $address
            application_filters = $application
        }
    }
)
$service = Get-Service -Name MpsSvc -ErrorAction Stop | Select-Object @{Name='name';Expression={$_.Name}}, @{Name='status';Expression={$_.Status.ToString()}}, @{Name='start_type';Expression={$_.StartType.ToString()}}
[pscustomobject]@{profiles=$profiles; rules=$ruleData; service=$service} | ConvertTo-Json -Depth 7 -Compress
"""


def _run(command, timeout=45):
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


def _normalize_bool(value):
    """Normalize PowerShell/JSON boolean representations to bool or None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None


def _empty_result():
    return {
        "platform": "Windows",
        "profiles": [],
        "enabled_rules": [],
        "rule_counts": {},
        "service": None,
        "sources": {},
        "errors": [],
        "collection_mode": "read-only",
    }


def collect_windows_firewall_info():
    """Collect local firewall profiles, enabled-rule metadata and associated filters."""
    result = _empty_result()
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", _WINDOWS_FIREWALL_SCRIPT,
    ]
    try:
        completed = _run(command)
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or "Windows Firewall query failed")
        data = json.loads(completed.stdout or "{}")
        if not isinstance(data, dict):
            raise ValueError("Unexpected PowerShell response shape")

        profiles = data.get("profiles") or []
        rules = data.get("rules") or []
        service = data.get("service")
        if isinstance(profiles, dict):
            profiles = [profiles]
        if isinstance(rules, dict):
            rules = [rules]
        if isinstance(service, list):
            service = service[0] if service else None

        result["profiles"] = [
            {
                "name": item.get("name"),
                "enabled": _normalize_bool(item.get("enabled")),
                "default_inbound_action": item.get("default_inbound_action"),
                "default_outbound_action": item.get("default_outbound_action"),
            }
            for item in profiles
        ]
        result["enabled_rules"] = [
            {
                "name": item.get("name"),
                "display_name": item.get("display_name"),
                "direction": item.get("direction"),
                "action": item.get("action"),
                "profile": item.get("profile"),
                "policy_store_source": item.get("policy_store_source"),
                "policy_store_source_type": item.get("policy_store_source_type"),
                "port_filters": item.get("port_filters") or [],
                "address_filters": item.get("address_filters") or [],
                "application_filters": item.get("application_filters") or [],
            }
            for item in rules
        ]
        counts = {}
        for rule in result["enabled_rules"]:
            key = "{},{}".format(
                str(rule.get("direction") or "Unknown"),
                str(rule.get("action") or "Unknown"),
            )
            counts[key] = counts.get(key, 0) + 1
        result["rule_counts"] = counts
        if service:
            result["service"] = {
                "name": service.get("name"),
                "status": service.get("status"),
                "start_type": service.get("start_type"),
            }

        for source in ("profiles", "rules", "service"):
            result["sources"][source] = {"status": "ok"}
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, TypeError) as error:
        for source in ("profiles", "rules", "service"):
            result["sources"][source] = {"status": "unavailable", "detail": str(error)}
        result["errors"].append({"source": "windows_firewall", "error": str(error)})
    return result
