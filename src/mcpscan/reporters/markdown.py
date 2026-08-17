from __future__ import annotations

from mcpscan import __version__
from mcpscan.constants import CHECKS_VERSION, NOT_CHECKED, SCANNER_NAME
from mcpscan.models import ConfigScanResult, ScanResult
from mcpscan.reporters.json_reporter import recommendation_for
from mcpscan.ruleset import RULESET_VERSION, ruleset_digest
from mcpscan.scoring import effective_severity
from mcpscan.tiers import TIER_DESCRIPTIONS, grade_label


def render_markdown(result: ScanResult) -> str:
    target = result.target.url or result.target.raw or result.target.kind.value
    server = result.server.name or "unknown"
    lines = [
        "# mcpscan report",
        "",
        "## Identity & Provenance",
        f"- Target: {target}",
        f"- Server: {server}",
        f"- Server version: {result.server.version or 'unknown'}",
        f"- Transport: {result.target.transport.value}",
        f"- Scanner: {SCANNER_NAME} {__version__}",
        f"- Checks version: {CHECKS_VERSION}",
        f"- Ruleset: v{RULESET_VERSION} digest {ruleset_digest()[:16]}",
        f"- Timestamp UTC: {result.scan.timestamp_utc}",
        f"- Reproduce command: `{result.scan.reproduce_command or 'unavailable'}`",
        "- Payload stored: false for all findings",
        "",
        "## Verdict Summary",
        f"- Recommendation: {recommendation_for(result)}",
        f"- Grade: {grade_label(result.grade, result.tier, result.checks_not_run)}",
        f"- Evidence tier: {result.tier.value} — {TIER_DESCRIPTIONS[result.tier]}",
        *(
            [
                f"- Replayed from: `{result.replayed_from.get('snapshot_path')}` captured "
                f"{result.replayed_from.get('captured_at')} "
                f"({result.replayed_from.get('age_human', 'unknown age')} ago); findings describe "
                "the surface as captured, not as it is now"
            ]
            if result.replayed_from
            else []
        ),
        f"- Purpose: {result.purpose_profile.category.value}",
        f"- Purpose source: {result.purpose_profile.category_source.value}",
        "- Expected capabilities: "
        + _capability_list(result.purpose_profile.expected_capabilities),
        f"- Critical: {result.counts.get('critical', 0)}",
        f"- High: {result.counts.get('high', 0)}",
        f"- Medium: {result.counts.get('medium', 0)}",
        f"- Low: {result.counts.get('low', 0)}",
        f"- Info: {result.counts.get('info', 0)}",
        "",
        "Top findings:",
    ]
    if result.checks_not_run:
        lines.extend(
            ["", f"## Not checked at this tier ({len(result.checks_not_run)})", ""]
            + [f"- `{i['check_id']}` {i['title']} — {i['reason']}" for i in result.checks_not_run]
            + [""]
        )
    if result.findings:
        lines.extend(f"- {_top_finding(finding)}" for finding in result.findings[:3])
    else:
        lines.append("- No findings.")
    lines.extend(
        [
            "",
            "## Findings",
        ]
    )
    if result.findings:
        lines.extend(
            [
                "",
                "| Adjusted severity | Verdict | Capability | OWASP | Check | Target | Evidence |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in result.findings:
            lines.append(
                "| {severity} | {verdict} | {capability} | {owasp} | {check} | {target} | {evidence} |".format(
                    severity=effective_severity(finding).value,
                    verdict=finding.contextual_verdict.value,
                    capability=finding.capability.value,
                    owasp=finding.owasp_mcp,
                    check=finding.id,
                    target=finding.target,
                    evidence=finding.evidence.replace("|", "\\|"),
                )
            )
    else:
        lines.extend(["", "No findings."])
    lines.append("")
    for finding in result.findings:
        lines.extend(
            [
                f"### {finding.id} - {finding.title}",
                f"Adjusted severity: {_severity_label(finding)}",
                f"Verdict: {finding.contextual_verdict.value}",
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
                "Verdict reasoning:",
                finding.verdict_reasoning,
                "",
                "Reference:",
                finding.reference,
                "",
            ]
        )
    lines.extend(
        [
            "## What We Did Not Check",
            *[f"- {item}" for item in NOT_CHECKED],
            "",
            "## Reproduce",
            f"`{result.scan.reproduce_command or 'unavailable'}`",
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
        "- Worst grade: "
        + (
            result.summary.worst_grade
            if result.summary.worst_grade
            and all(s.result.checks_not_run == [] for s in result.server_results)
            else (
                "not assessed (no server was scanned)"
                if not result.summary.worst_grade
                else f"{result.summary.worst_grade} (of the checks that ran; some did not)"
            )
        ),
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
                        f"Severity: {_severity_label(finding)}",
                        f"Verdict: {finding.contextual_verdict.value}",
                        f"Capability: {finding.capability.value}",
                        f"OWASP MCP: {finding.owasp_mcp}",
                        f"Target: {finding.target}",
                        f"Payload stored: {str(finding.payload_stored).lower()}",
                        "",
                        "Verdict reasoning:",
                        finding.verdict_reasoning,
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


def _severity_label(finding) -> str:
    adjusted = effective_severity(finding)
    if adjusted == finding.severity:
        return adjusted.value.title()
    return f"{adjusted.value.title()} (original: {finding.severity.value.title()})"


def _top_finding(finding) -> str:
    return (
        f"{effective_severity(finding).value.upper()} {finding.id} on "
        f"{finding.target}: {finding.evidence}"
    )
