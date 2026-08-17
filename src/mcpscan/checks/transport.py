from __future__ import annotations

from urllib.parse import urlparse

from mcpscan.capabilities import Capability
from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity, TargetKind
from mcpscan.tiers import ALL_TIERS, EvidenceTier

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class UnauthenticatedRemoteServerCheck(Check):
    id = "MCP-040"
    title = "Unauthenticated remote server"
    severity = Severity.HIGH
    default_capability = Capability.TRANSPORT_SECURITY
    owasp_mcp = "MCP07"
    # Live only. The finding rests on `unauthenticated_enumeration`, which is
    # an observation about what the server actually allowed — not something a
    # config file or a stored snapshot can tell you.
    requires = frozenset({EvidenceTier.LIVE})

    def run(self, ctx: ScanContext) -> list[Finding]:
        if (
            ctx.target.kind == TargetKind.URL
            and not ctx.target.headers
            and ctx.unauthenticated_enumeration
        ):
            return [
                self.finding(
                    target=ctx.target.url or "remote",
                    evidence="Remote target allowed MCP initialize/enumeration without caller-supplied authentication header.",
                    remediation="Require authentication for remote MCP servers and avoid exposing enumeration to unauthenticated callers.",
                )
            ]
        return []


class MissingTLSCheck(Check):
    id = "MCP-041"
    title = "Missing TLS"
    severity = Severity.HIGH
    default_capability = Capability.TRANSPORT_SECURITY
    owasp_mcp = "MCP07"
    # The scheme is in the config. Nothing needs to be started to see that a
    # remote target is plaintext, which makes this the first check that is
    # genuinely useful with no server at all.
    requires = ALL_TIERS

    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target.kind != TargetKind.URL or not ctx.target.url:
            return []
        parsed = urlparse(ctx.target.url)
        if parsed.scheme != "http":
            return []
        host = parsed.hostname or ""
        severity = Severity.MEDIUM if host in LOCAL_HOSTS else Severity.HIGH
        return [
            self.finding(
                severity=severity,
                target=ctx.target.url,
                evidence="Remote MCP target uses plaintext HTTP.",
                remediation="Use HTTPS for remote MCP transports. Keep plaintext only for local development endpoints.",
            )
        ]
