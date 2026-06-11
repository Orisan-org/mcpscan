from mcpscan.capabilities import Capability
from mcpscan.engine import sort_findings
from mcpscan.models import Finding, Severity


def _finding(id_: str, severity: Severity, target: str) -> Finding:
    return Finding(
        id=id_,
        title="title",
        severity=severity,
        capability=Capability.OTHER,
        owasp_mcp="MCP00",
        target=target,
        evidence="evidence",
        remediation="remediation",
        reference="reference",
    )


def test_sort_findings_by_severity_id_target() -> None:
    findings = sort_findings(
        [
            _finding("MCP-050", Severity.MEDIUM, "b"),
            _finding("MCP-001", Severity.CRITICAL, "b"),
            _finding("MCP-001", Severity.CRITICAL, "a"),
        ]
    )

    assert [(item.severity, item.id, item.target) for item in findings] == [
        (Severity.CRITICAL, "MCP-001", "a"),
        (Severity.CRITICAL, "MCP-001", "b"),
        (Severity.MEDIUM, "MCP-050", "b"),
    ]
