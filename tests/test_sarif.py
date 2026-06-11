from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate

from mcpscan.reporters.sarif import render_sarif
from mcpscan.scanner import scan_context
from tests.helpers import malicious_context


def test_sarif_validates_and_contains_finding_properties() -> None:
    payload = json.loads(render_sarif(scan_context(malicious_context())))
    schema = json.loads(Path("tests/data/sarif-2.1.0.schema.json").read_text())

    validate(payload, schema)
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpscan"
    assert any(rule["id"] == "MCP-010" for rule in run["tool"]["driver"]["rules"])
    assert run["results"]
    first = run["results"][0]
    assert first["level"] in {"error", "warning", "note"}
    assert first["properties"]["payload_stored"] is False
    assert first["properties"]["capability"]
    assert first["properties"]["owasp_mcp"].startswith("MCP")
    assert first["properties"]["contextual_verdict"]
    assert first["properties"]["original_severity"]
