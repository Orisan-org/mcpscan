from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext
from mcpscan.scoring import effective_severity
from mcpscan.tiers import CheckNotRun, reason_for
from mcpscan.utils.severity import severity_sort_value


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (severity_sort_value(effective_severity(item)), item.id, item.target),
    )


def select_checks(ctx: ScanContext, checks: list[Check]) -> tuple[list[Check], list[CheckNotRun]]:
    """Split the catalogue into what this tier can run and what it cannot.

    A check whose inputs the tier does not supply is NOT run. Running it anyway
    would have it iterate an empty tool list and return nothing, which reads
    identically to a clean result — the false-assurance case the tier system
    exists to prevent.
    """
    runnable: list[Check] = []
    skipped: list[CheckNotRun] = []
    for check in checks:
        if ctx.tier in check.requires:
            runnable.append(check)
        else:
            skipped.append(
                CheckNotRun(
                    check_id=check.id,
                    title=check.title,
                    owasp_mcp=check.owasp_mcp,
                    reason=reason_for(check.id, check.requires, ctx.tier),
                )
            )
    skipped.sort(key=lambda item: item.check_id)
    return runnable, skipped


def run_checks(ctx: ScanContext, checks: list[Check]) -> list[Finding]:
    """Findings only. Kept for callers that do not need the skip list."""
    findings, _ = run_checks_with_coverage(ctx, checks)
    return findings


def run_checks_with_coverage(
    ctx: ScanContext, checks: list[Check]
) -> tuple[list[Finding], list[CheckNotRun]]:
    runnable, skipped = select_checks(ctx, checks)
    findings: list[Finding] = []
    for check in runnable:
        findings.extend(check.run(ctx))
    return sort_findings(findings), skipped
