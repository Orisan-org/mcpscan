from mcpscan.models import Severity
from mcpscan.scanner import scan_context
from mcpscan.utils.severity import severity_gte
from tests.helpers import benign_context, malicious_context


def test_benign_context_grade_a() -> None:
    result = scan_context(benign_context())

    assert result.grade == "A"
    assert result.findings == []


def test_malicious_context_expected_findings_and_grade_f() -> None:
    result = scan_context(malicious_context())
    ids = {finding.id for finding in result.findings}

    assert {"MCP-001", "MCP-010", "MCP-020", "MCP-021", "MCP-030", "MCP-040", "MCP-041"}.issubset(
        ids
    )
    assert result.grade == "F"
    assert any(severity_gte(finding.severity, Severity.HIGH) for finding in result.findings)
