from mcpscan.capabilities import OWASP_MCP_REFERENCES, Capability
from mcpscan.checks.registry import active_checks, check_catalogue
from mcpscan.scanner import scan_context
from tests.helpers import malicious_context


def test_every_active_check_has_capability_and_owasp_metadata() -> None:
    for check in active_checks():
        assert isinstance(check.default_capability, Capability)
        assert check.owasp_mcp in OWASP_MCP_REFERENCES
        assert check.reference == OWASP_MCP_REFERENCES[check.owasp_mcp]


def test_check_catalogue_includes_deferred_metadata() -> None:
    entries = check_catalogue()

    assert all(isinstance(entry.capability, Capability) for entry in entries)
    assert all(entry.owasp_mcp in OWASP_MCP_REFERENCES for entry in entries)


def test_malicious_context_findings_include_concrete_capabilities() -> None:
    result = scan_context(malicious_context())
    capabilities = {finding.capability for finding in result.findings}

    assert Capability.SHELL_EXEC in capabilities
    assert Capability.CREDENTIAL_ACCESS in capabilities
    assert all(finding.owasp_mcp.startswith("MCP") for finding in result.findings)
