from mcpscan.models import Severity

ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_gte(actual: Severity, threshold: Severity) -> bool:
    return ORDER[actual] >= ORDER[threshold]


def severity_sort_value(severity: Severity) -> int:
    return -ORDER[severity]
