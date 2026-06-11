from mcpscan.capabilities import Capability
from mcpscan.models import Finding, Severity
from mcpscan.utils.redact import mask_value, redact_secret
from mcpscan.utils.severity import severity_gte


def test_finding_payload_stored_defaults_false() -> None:
    finding = Finding(
        id="MCP-X",
        title="Example",
        severity=Severity.HIGH,
        capability=Capability.OTHER,
        owasp_mcp="MCP00",
        target="tool",
        evidence="redacted evidence",
        remediation="fix it",
        reference="ref",
    )

    assert finding.payload_stored is False


def test_severity_ordering() -> None:
    assert severity_gte(Severity.HIGH, Severity.MEDIUM)
    assert not severity_gte(Severity.LOW, Severity.HIGH)


def test_redaction_masks_values() -> None:
    assert mask_value("abcdefghi") == "***"
    assert mask_value("abcdefghijklmnop") == "abcd...mnop"
    assert (
        redact_secret("postgres://user:password@db.example/app")
        == "postgres://user:***@db.example/app"
    )
