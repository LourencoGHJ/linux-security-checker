"""Cross-platform scan orchestration.

Platform-specific checks are loaded only on platforms that support them.
The scanner never labels an unsupported check as a security failure.
"""


def _load_linux_checks():
    """Load checks that currently depend on Linux facilities."""
    from golfinho.checks.firewall import check_firewall
    from golfinho.checks.users import check_users
    from golfinho.checks.services import check_services
    from golfinho.checks.permissions import check_permissions

    return {
        "firewall": check_firewall,
        "users": check_users,
        "services": check_services,
        "permissions": check_permissions,
    }


def _finding_from_rule(rule_id, evidence, confidence="MEDIUM"):
    from golfinho.engine.evidence import create_finding
    from golfinho.engine.rules import get_rule

    rule = get_rule(rule_id)
    if rule is None:
        return None

    return create_finding(
        title=rule["title"],
        category=rule["category"],
        severity=rule["severity"],
        description=rule["description"],
        evidence=evidence,
        recommendation=rule["recommendation"],
        rule_id=rule_id,
        confidence=confidence,
    )


def analyze_results(results):
    findings = []
    firewall = results.get("firewall") or {}

    if "PERMISSION_DENIED" in firewall.values():
        finding = _finding_from_rule(
            "GOL-FW-001",
            {
                "detected_states": firewall,
                "observation": "Consulta do firewall incompleta.",
            },
            confidence="HIGH",
        )
        if finding:
            findings.append(finding)

    services = results.get("services") or {}
    failed_services = services.get("failed_services", [])
    if failed_services:
        finding = _finding_from_rule(
            "GOL-SVC-001",
            {"failed_services": failed_services, "count": len(failed_services)},
            confidence="HIGH",
        )
        if finding:
            findings.append(finding)

    permissions = results.get("permissions") or []
    for item in permissions:
        if item.get("status") in {"OK", "NOT_FOUND"}:
            continue
        finding = _finding_from_rule(
            "GOL-PERM-001",
            {
                "path": item.get("path"),
                "status": item.get("status"),
                "permissions": item.get("permissions"),
                "owner_uid": item.get("owner_uid"),
                "group_gid": item.get("group_gid"),
                "findings": item.get("findings", []),
            },
        )
        if finding:
            finding["filename"] = item.get("path")
            findings.append(finding)

    return findings


def enrich_findings(findings, system_info):
    from golfinho.intelligence.references import get_references
    from golfinho.intelligence.prompts import generate_investigation_prompt

    for finding in findings:
        finding["references"] = get_references(finding["category"])
        finding["investigation_prompt"] = generate_investigation_prompt(
            finding, system_info
        )
    return findings


def run_security_scan():
    """Run the checks supported by the current operating system."""
    from golfinho.platform.detector import detect_platform

    results = {
        "platform": None,
        "firewall": None,
        "users": None,
        "services": None,
        "permissions": None,
        "errors": [],
        "checks_skipped": [],
        "findings": [],
    }

    try:
        results["platform"] = detect_platform()
    except Exception as error:
        results["errors"].append({"check": "platform", "error": str(error)})
        return results

    family = results["platform"].get("family", "").lower()
    if family != "linux":
        results["checks_skipped"] = [
            {
                "check": name,
                "reason": "NOT_IMPLEMENTED_FOR_PLATFORM",
            }
            for name in ("firewall", "users", "services", "permissions")
        ]
        return results

    try:
        checks = _load_linux_checks()
    except Exception as error:
        results["errors"].append({"check": "load_linux_checks", "error": str(error)})
        return results

    for name, check in checks.items():
        try:
            results[name] = check()
        except Exception as error:
            results["errors"].append({"check": name, "error": str(error)})

    findings = analyze_results(results)
    results["findings"] = enrich_findings(findings, results["platform"])
    return results
