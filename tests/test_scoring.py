from mcpscan.capabilities import Capability
from mcpscan.models import Finding, Severity
from mcpscan.scoring import grade_for


def _finding(severity: Severity) -> Finding:
    return Finding(
        id="MCP-X",
        title="title",
        severity=severity,
        capability=Capability.OTHER,
        owasp_mcp="MCP00",
        target="target",
        evidence="evidence",
        remediation="remediation",
        reference="reference",
    )


def test_grades() -> None:
    assert grade_for([]) == "A"
    assert grade_for([_finding(Severity.LOW)]) == "B"
    assert grade_for([_finding(Severity.MEDIUM)]) == "C"
    assert grade_for([_finding(Severity.HIGH)]) == "D"
    assert grade_for([_finding(Severity.CRITICAL)]) == "F"
