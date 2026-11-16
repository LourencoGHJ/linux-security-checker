from golfinho.checks.firewall import check_firewall
from golfinho.checks.users import check_users
from golfinho.checks.services import check_services
from golfinho.checks.permissions import check_permissions

from golfinho.engine.evidence import create_finding
from golfinho.engine.rules import get_rule
from golfinho.platform.detector import detect_platform

from golfinho.intelligence.references import get_references
from golfinho.intelligence.prompts import generate_investigation_prompt


def _finding_from_rule(rule_id, evidence, confidence="MEDIUM"):
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
            {
                "failed_services": failed_services,
                "count": len(failed_services),
            },
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
    for finding in findings:
        finding["references"] = get_references(
            finding["category"]
        )

        finding["investigation_prompt"] = (
            generate_investigation_prompt(
                finding,
                system_info,
            )
        )

    return findings


def run_security_scan():
    results = {
        "platform": None,
        "firewall": None,
        "users": None,
        "services": None,
        "permissions": None,
        "errors": [],
        "findings": [],
    }

    try:
        results["platform"] = detect_platform()
    except Exception as error:
        results["errors"].append({
            "check": "platform",
            "error": str(error),
        })

    checks = {
        "firewall": check_firewall,
        "users": check_users,
        "services": check_services,
        "permissions": check_permissions,
    }

    for name, check in checks.items():
        try:
            results[name] = check()
        except Exception as error:
            results["errors"].append({
                "check": name,
                "error": str(error),
            })

    findings = analyze_results(results)

    results["findings"] = enrich_findings(
        findings,
        results["platform"],
    )

    return results
