from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext
from mcpscan.scoring import effective_severity
from mcpscan.utils.severity import severity_sort_value


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (severity_sort_value(effective_severity(item)), item.id, item.target),
    )


def run_checks(ctx: ScanContext, checks: list[Check]) -> list[Finding]:
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check.run(ctx))
    return sort_findings(findings)
