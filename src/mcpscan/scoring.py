from mcpscan.models import Finding, Severity


def effective_severity(finding: Finding) -> Severity:
    return finding.adjusted_severity or finding.severity


def count_findings(findings: list[Finding]) -> dict[str, int]:
    return {
        severity.value: sum(1 for item in findings if effective_severity(item) == severity)
        for severity in Severity
    }


def grade_for(findings: list[Finding]) -> str:
    severities = {effective_severity(finding) for finding in findings}
    if Severity.CRITICAL in severities:
        return "F"
    if Severity.HIGH in severities:
        return "D"
    if Severity.MEDIUM in severities:
        return "C"
    if Severity.LOW in severities or Severity.INFO in severities:
        return "B"
    return "A"
