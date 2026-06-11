import json
from importlib.resources import files

from jsonschema import validate

from mcpscan.models import (
    ConfigScanResult,
    ConfigScanSummary,
    ConfigServerResult,
    Transport,
)
from mcpscan.reporters.json_reporter import render_config_json, render_json
from mcpscan.reporters.markdown import render_config_markdown, render_markdown
from mcpscan.reporters.terminal import render_config_terminal, render_terminal
from mcpscan.scanner import scan_context
from tests.helpers import malicious_context


def test_json_contains_payload_stored_false() -> None:
    payload = json.loads(render_json(scan_context(malicious_context())))

    validate(payload, json.loads(files("mcpscan.data").joinpath("report.schema.json").read_text()))
    assert payload["report_version"] == "2.0"
    assert payload["verdict_summary"]["recommendation"] == "do_not_connect"
    assert payload["findings"]
    assert all(finding["payload_stored"] is False for finding in payload["findings"])
    assert all(finding["capability"] for finding in payload["findings"])
    assert all(finding["owasp_mcp"].startswith("MCP") for finding in payload["findings"])
    assert payload["not_checked"]


def test_markdown_includes_remediation() -> None:
    report = render_markdown(scan_context(malicious_context()))

    assert "## Identity & Provenance" in report
    assert "## Verdict Summary" in report
    assert "## Findings" in report
    assert "## What We Did Not Check" in report
    assert "## Reproduce" in report
    assert "Remediation:" in report
    assert "Capability:" in report
    assert "OWASP MCP:" in report


def test_terminal_does_not_crash() -> None:
    report = render_terminal(scan_context(malicious_context()), no_color=True)

    assert "Grade:" in report


def config_result() -> ConfigScanResult:
    result = scan_context(malicious_context())
    return ConfigScanResult(
        config_paths=["./mcp.json"],
        server_results=[
            ConfigServerResult(
                name="malicious",
                source_path="./mcp.json",
                transport=Transport.STDIO,
                env_names=["SECRET"],
                result=result,
            )
        ],
        summary=ConfigScanSummary(
            configs_found=1,
            servers_total=1,
            servers_scanned=1,
            servers_failed=0,
            servers_skipped=0,
            findings_total=len(result.findings),
            worst_grade=result.grade,
        ),
    )


def test_config_json_report_shape_and_payload_contract() -> None:
    payload = json.loads(render_config_json(config_result()))

    assert payload["report_version"] == "2.0"
    assert payload["config"]["servers_scanned"] == 1
    findings = payload["server_results"][0]["findings"]
    assert findings
    assert all(finding["payload_stored"] is False for finding in findings)
    assert "SECRET" in payload["server_results"][0]["env"]["names"]


def test_config_markdown_report_has_per_server_summary() -> None:
    report = render_config_markdown(config_result())

    assert "# mcpscan config report" in report
    assert "### malicious" in report
    assert "Payload stored: false" in report


def test_config_terminal_report_has_privacy_line() -> None:
    report = render_config_terminal(config_result(), no_color=True)

    assert "mcpscan config report" in report
    assert "Privacy: payload_stored=false for all findings" in report
