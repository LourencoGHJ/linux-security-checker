from datetime import datetime, timezone
from uuid import uuid4

from golfinho.engine.severity import classify_severity


def create_finding(
    title,
    category,
    severity,
    description,
    evidence,
    recommendation,
    source=None,
    filename=None,
    rule_id=None,
    confidence="MEDIUM",
):
    return {
        "id": f"GOL-{uuid4().hex[:8].upper()}",
        "rule_id": rule_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "title": title,
        "category": category,
        "severity": classify_severity(severity),
        "confidence": confidence,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
        "filename": filename,
    }
