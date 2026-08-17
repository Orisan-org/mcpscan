from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_EGRESS = "network_egress"
    SHELL_EXEC = "shell_exec"
    CODE_EVAL = "code_eval"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXPOSURE = "data_exposure"
    PROMPT_ANOMALY = "prompt_anomaly"
    TRANSPORT_SECURITY = "transport_security"
    IDENTITY_SPOOF = "identity_spoof"
    SURFACE_DRIFT = "surface_drift"
    OTHER = "other"


# The full OWASP MCP Top 10, as reference text. Having an entry here says only
# that the category exists and what it is called. It does NOT say mcpscan checks
# for it — see UNCOVERED_OWASP_MCP below and owasp_coverage(), which derive the
# truth from the check registry rather than from this table.
OWASP_MCP_REFERENCES: dict[str, str] = {
    "MCP01": "OWASP MCP Top 10: Credential exposure",
    "MCP02": "OWASP MCP Top 10: Excessive permissions",
    "MCP03": "OWASP MCP Top 10: Tool poisoning and rug pull attacks",
    "MCP04": "OWASP MCP Top 10: Supply chain risk",
    "MCP05": "OWASP MCP Top 10: Tool invocation injection",
    "MCP06": "OWASP MCP Top 10: Tool shadowing",
    "MCP07": "OWASP MCP Top 10: Insecure transport and authentication",
    "MCP08": "OWASP MCP Top 10: Audit and logging gaps",
    "MCP09": "OWASP MCP Top 10: Identity and package spoofing",
    "MCP10": "OWASP MCP Top 10: Sensitive data exposure",
}


#: Categories with reference text above but no check emitting them.
#:
#: Declared explicitly so the gap is visible in the code, not only in the README.
#: tests/test_owasp_coverage.py asserts this set matches what the registry
#: actually emits, in BOTH directions: adding a check for one of these fails the
#: build until the category is removed from here and the README is updated, and
#: deleting a check fails the build until it is added. The set cannot silently
#: drift away from reality, which is the failure this guards.
UNCOVERED_OWASP_MCP: frozenset[str] = frozenset({"MCP04", "MCP06", "MCP08"})

#: Why each uncovered category is uncovered. Shown to operators verbatim.
UNCOVERED_REASONS: dict[str, str] = {
    "MCP04": "no check: dependency and package provenance are not inspected",
    "MCP06": "no check: cross-server tool shadowing is not detected",
    "MCP08": "no check: the server's own audit and logging behaviour is not assessed",
}


def owasp_reference(owasp_mcp: str) -> str:
    return OWASP_MCP_REFERENCES.get(owasp_mcp, "OWASP MCP Top 10")


def covered_owasp_mcp() -> frozenset[str]:
    """Categories some active check actually emits.

    Derived from the registry at call time. A hand-maintained list here would be
    the thing that goes stale, and a stale coverage claim is the overstatement
    this function exists to prevent.
    """
    from mcpscan.checks.registry import check_catalogue

    return frozenset(entry.owasp_mcp for entry in check_catalogue() if entry.owasp_mcp)


def owasp_coverage() -> dict[str, dict[str, str]]:
    """Every category, and whether mcpscan checks for it.

    ``status`` is ``checked`` or ``no_check_implemented``. There is deliberately
    no third value that reads as reassuring: a category either has a check
    behind it or it does not.
    """
    covered = covered_owasp_mcp()
    return {
        category: {
            "title": title,
            "status": "checked" if category in covered else "no_check_implemented",
            "detail": "" if category in covered else UNCOVERED_REASONS.get(category, "no check implemented"),
        }
        for category, title in sorted(OWASP_MCP_REFERENCES.items())
    }
