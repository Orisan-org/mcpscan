from __future__ import annotations

from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity

KNOWN_NAMES = (
    "filesystem",
    "github",
    "git",
    "postgres",
    "slack",
    "google-drive",
    "puppeteer",
    "stripe",
    "sqlite",
    "brave-search",
)


class LookalikeNameCheck(Check):
    id = "MCP-050"
    title = "Lookalike or typosquat name"
    severity = Severity.MEDIUM
    reference = "OWASP MCP Top 10: Supply chain"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        names = [name for name in [ctx.server.name, *(tool.name for tool in ctx.tools)] if name]
        for name in names:
            normalized = _normalize(name)
            for known in KNOWN_NAMES:
                if normalized == known:
                    continue
                if _levenshtein(normalized, known) == 1 and len(normalized) >= 5:
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
    return value.lower().replace("_", "-").strip()


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
