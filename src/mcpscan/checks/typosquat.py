from __future__ import annotations

from mcpscan.capabilities import Capability
from mcpscan.checks.base import Check
from mcpscan.checks.known_mcp_names import KNOWN_MCP_SERVER_NAMES
from mcpscan.models import Finding, ScanContext, Severity

COMMON_PACKAGE_PREFIXES = (
    "server-",
    "mcp-server-",
    "mcp-",
)


class LookalikeNameCheck(Check):
    id = "MCP-050"
    title = "Static known-name lookalike check"
    severity = Severity.MEDIUM
    default_capability = Capability.IDENTITY_SPOOF
    owasp_mcp = "MCP09"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        names = [name for name in [ctx.server.name, *(tool.name for tool in ctx.tools)] if name]
        alerted_normalized_names: set[str] = set()
        for name in names:
            normalized = _normalize(name)
            if normalized in alerted_normalized_names:
                continue
            for known in KNOWN_MCP_SERVER_NAMES:
                if normalized == known:
                    continue
                if _levenshtein(normalized, known) == 1 and len(normalized) >= 5:
                    alerted_normalized_names.add(normalized)
                    findings.append(
                        self.finding(
                            target=name,
                            evidence=f"Name {name!r} is visually similar to known MCP server name {known!r}.",
                            remediation="Verify package provenance, repository ownership, and installation source before trusting this server.",
                        )
                    )
                    break
        return findings


def _normalize(value: str) -> str:
    normalized = value.lower().replace("_", "-").strip()
    normalized = normalized.removeprefix("@")
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    for prefix in COMMON_PACKAGE_PREFIXES:
        normalized = normalized.removeprefix(prefix)
    return normalized


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 1:
        return 2
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (ca != cb),
                )
            )
        previous = current
    return previous[-1]
