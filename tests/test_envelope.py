import json

from mcpscan.models import (
    ConfigScanResult,
    ConfigScanSummary,
    ConfigServerResult,
    Transport,
)
from mcpscan.reporters.envelope import render_config_envelope, render_envelope
from mcpscan.scanner import scan_context
from tests.helpers import malicious_context


def test_render_envelope_maps_findings_without_payloads() -> None:
    payload = json.loads(render_envelope(scan_context(malicious_context())))

    assert payload["schema_version"] == "1.0.0"
    assert payload["producer"]["tool"] == "mcpscan"
    assert payload["target"]["type"] == "mcp_server"
    assert payload["findings"]
    first = payload["findings"][0]
    assert first["id"].startswith("f_")
    assert first["rule_id"].startswith("MCP-")
    assert first["evidence"]["redacted"] is True
    assert first["status"] == "open"
    assert first["taxonomy"][0]["framework"] == "owasp_mcp_top10"
    assert "payload_stored" not in json.dumps(payload)


def test_render_config_envelope_includes_inventory_and_partial_coverage() -> None:
    result = scan_context(malicious_context())
    config_result = ConfigScanResult(
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

    payload = json.loads(render_config_envelope(config_result))

    assert payload["target"]["type"] == "fleet"
    assert payload["inventory"][0]["id"].startswith("i_")
    assert payload["inventory"][0]["kind"] == "mcp_server"
    assert payload["coverage"][0]["status"] == "partial"
    assert payload["coverage"][0]["enforced"] is False
    assert payload["findings"]
