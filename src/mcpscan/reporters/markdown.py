from __future__ import annotations

from mcpscan.models import ScanResult


def render_markdown(result: ScanResult) -> str:
    target = result.target.url or result.target.raw or result.target.kind.value
    server = result.server.name or "unknown"
    lines = [
        "# mcpscan report",
        "",
        "## Summary",
        f"- Target: {target}",
        f"- Server: {server}",
        f"- Transport: {result.target.transport.value}",
        f"- Grade: {result.grade}",
        f"- Critical: {result.counts.get('critical', 0)}",
        f"- High: {result.counts.get('high', 0)}",
        f"- Medium: {result.counts.get('medium', 0)}",
        f"- Low: {result.counts.get('low', 0)}",
        "",
        "## Findings",
    ]
    if not result.findings:
        lines.extend(["", "No findings."])
    for finding in result.findings:
        lines.extend(
            [
                "",
                f"### {finding.id} - {finding.title}",
                f"Severity: {finding.severity.value.title()}  ",
                f"Target: {finding.target}  ",
                f"Payload stored: {str(finding.payload_stored).lower()}  ",
                "",
                "Evidence:",
                finding.evidence,
                "",
                "Remediation:",
                finding.remediation,
                "",
                "Reference:",
                finding.reference,
            ]
        )
    if result.warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {warning}" for warning in result.warnings)
    return "\n".join(lines) + "\n"
