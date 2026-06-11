from __future__ import annotations

import json

from mcpscan.adjudicate import adjudicate_findings
from mcpscan.capabilities import Capability
from mcpscan.models import (
    ContextualVerdict,
    ExposedTool,
    Finding,
    PurposeCategory,
    ScanContext,
    Severity,
)
from mcpscan.reporters.json_reporter import render_json
from mcpscan.scanner import scan_context
from tests.helpers import command_target, malicious_context


def test_filesystem_file_capability_is_expected_and_downgraded() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[ExposedTool(name="read_file", description="Read files from a directory.")],
    )

    result = scan_context(ctx, purpose_category=PurposeCategory.FILESYSTEM)
    finding = _only(result.findings, "MCP-010")

    assert finding.contextual_verdict == ContextualVerdict.EXPECTED_BY_PURPOSE
    assert finding.original_severity == Severity.HIGH
    assert finding.adjusted_severity == Severity.INFO
    assert result.grade == "B"


def test_weather_server_file_capability_is_undeclared_and_escalated() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[ExposedTool(name="read_file", description="Read files from a directory.")],
    )

    result = scan_context(ctx, purpose_text="weather server")
    finding = _only(result.findings, "MCP-010")

    assert finding.contextual_verdict == ContextualVerdict.UNDECLARED
    assert finding.original_severity == Severity.HIGH
    assert finding.adjusted_severity == Severity.CRITICAL
    assert result.grade == "F"


def test_declared_url_fetch_capability_is_unexpected_but_not_escalated() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="fetch",
                description="Fetch a URL.",
                input_schema={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                },
            )
        ],
    )

    result = scan_context(ctx, purpose_text="weather server that can fetch URLs")
    finding = _only(result.findings, "MCP-010")

    assert finding.contextual_verdict == ContextualVerdict.UNEXPECTED
    assert finding.original_severity == Severity.HIGH
    assert finding.adjusted_severity == Severity.HIGH
    assert result.grade == "D"


def test_non_downgrade_eligible_check_keeps_original_severity() -> None:
    ctx = ScanContext(target=command_target())
    finding = Finding(
        id="MCP-020",
        title="Synthetic secret exposure",
        severity=Severity.CRITICAL,
        capability=Capability.FILE_READ,
        owasp_mcp="MCP01",
        target="synthetic",
        evidence="Synthetic evidence.",
        remediation="Synthetic remediation.",
        reference="Synthetic reference.",
    )

    result = scan_context(ctx, purpose_category=PurposeCategory.FILESYSTEM)
    adjudicated = result.findings + []
    adjudicated.append(finding)

    checked = adjudicate_findings(adjudicated, result.purpose_profile)[-1]

    assert checked.contextual_verdict == ContextualVerdict.EXPECTED_BY_PURPOSE
    assert checked.adjusted_severity == Severity.CRITICAL


def test_no_purpose_info_keeps_severities_unadjudicated() -> None:
    result = scan_context(malicious_context())

    assert result.findings
    assert all(
        finding.contextual_verdict == ContextualVerdict.UNADJUDICATED for finding in result.findings
    )
    assert all(finding.adjusted_severity == finding.severity for finding in result.findings)


def test_same_scan_emits_identical_json() -> None:
    first = json.loads(
        render_json(scan_context(malicious_context(), purpose_category=PurposeCategory.FILESYSTEM))
    )
    second = json.loads(
        render_json(scan_context(malicious_context(), purpose_category=PurposeCategory.FILESYSTEM))
    )
    first["scan"]["timestamp_utc"] = "<timestamp>"
    second["scan"]["timestamp_utc"] = "<timestamp>"

    assert first == second


def test_adjudication_does_not_drop_findings() -> None:
    result = scan_context(malicious_context(), purpose_category=PurposeCategory.FILESYSTEM)
    readjudicated = adjudicate_findings(result.findings, result.purpose_profile)

    assert len(readjudicated) == len(result.findings)


def _only(findings: list[Finding], check_id: str) -> Finding:
    matches = [finding for finding in findings if finding.id == check_id]
    assert len(matches) == 1
    return matches[0]
