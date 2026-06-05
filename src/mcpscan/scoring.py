from mcpscan.models import Finding, Severity


def count_findings(findings: list[Finding]) -> dict[str, int]:
    return {
        severity.value: sum(1 for item in findings if item.severity == severity)
        for severity in Severity
    }


def grade_for(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    if Severity.CRITICAL in severities:
        return "F"
    if Severity.HIGH in severities:
        return "D"
    if Severity.MEDIUM in severities:
        return "C"
    if Severity.LOW in severities or Severity.INFO in severities:
        return "B"
    return "A"
