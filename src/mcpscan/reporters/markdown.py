from __future__ import annotations

from mcpscan.models import ConfigScanResult, ScanResult


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
        f"- Purpose: {result.purpose_profile.category.value}",
        f"- Purpose source: {result.purpose_profile.category_source.value}",
        "- Expected capabilities: "
        + _capability_list(result.purpose_profile.expected_capabilities),
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
                f"Severity: {finding.severity.value.title()}",
                f"Capability: {finding.capability.value}",
                f"OWASP MCP: {finding.owasp_mcp}",
                f"Target: {finding.target}",
                f"Payload stored: {str(finding.payload_stored).lower()}",
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


def render_config_markdown(result: ConfigScanResult) -> str:
    lines = [
        "# mcpscan config report",
        "",
        "## Summary",
        f"- Configs found: {result.summary.configs_found}",
        f"- Servers total: {result.summary.servers_total}",
        f"- Servers scanned: {result.summary.servers_scanned}",
        f"- Servers failed: {result.summary.servers_failed}",
        f"- Servers skipped: {result.summary.servers_skipped}",
        f"- Findings total: {result.summary.findings_total}",
        f"- Worst grade: {result.summary.worst_grade}",
        "- Payload stored: false for all findings",
        "",
        "## Config Files",
    ]
    lines.extend(f"- {path}" for path in result.config_paths)
    lines.append("")
    lines.append("## Server Results")
    if not result.server_results:
        lines.extend(["", "No servers scanned successfully."])
    for server in result.server_results:
        lines.extend(
            [
                "",
                f"### {server.name}",
                f"- Source: {server.source_path}",
                f"- Transport: {server.transport.value}",
                f"- Purpose: {server.result.purpose_profile.category.value}",
                f"- Purpose source: {server.result.purpose_profile.category_source.value}",
                "- Expected capabilities: "
                + _capability_list(server.result.purpose_profile.expected_capabilities),
                f"- Grade: {server.result.grade}",
                f"- Env names observed: {len(server.env_names)}",
                f"- Findings: {len(server.result.findings)}",
            ]
        )
        if server.result.findings:
            for finding in server.result.findings:
                lines.extend(
                    [
                        "",
                        f"#### {finding.id} - {finding.title}",
                        f"Severity: {finding.severity.value.title()}",
                        f"Capability: {finding.capability.value}",
                        f"OWASP MCP: {finding.owasp_mcp}",
                        f"Target: {finding.target}",
                        f"Payload stored: {str(finding.payload_stored).lower()}",
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
        else:
            lines.extend(["", "No findings."])

    if result.failures:
        lines.extend(["", "## Failures"])
        for failure in result.failures:
            lines.append(f"- {failure.name}: {failure.error}")

    if result.skipped:
        lines.extend(["", "## Skipped Servers"])
        for skipped in result.skipped:
            lines.append(f"- {skipped.name}: {skipped.reason}")

    return "\n".join(lines) + "\n"


def _capability_list(capabilities: list) -> str:
    if not capabilities:
        return "none"
    return ", ".join(capability.value for capability in capabilities)
