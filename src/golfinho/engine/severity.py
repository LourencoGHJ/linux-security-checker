SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


def classify_severity(level):
    normalized = str(level).upper()

    if normalized not in SEVERITY_LEVELS:
        return "UNKNOWN"

    return normalized


def severity_score(level):
    normalized = classify_severity(level)
    return SEVERITY_LEVELS[normalized]
