from __future__ import annotations

from urllib.parse import urlparse

from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity, TargetKind

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class UnauthenticatedRemoteServerCheck(Check):
    id = "MCP-040"
    title = "Unauthenticated remote server"
    severity = Severity.HIGH
    reference = "OWASP MCP Top 10: Auth and transport"

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
    reference = "OWASP MCP Top 10: Auth and transport"

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
