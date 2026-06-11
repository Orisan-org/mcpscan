from __future__ import annotations

from mcpscan.capabilities import Capability
from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity
from mcpscan.utils.text import iter_strings

SENSITIVE_SIGNALS = (
    ".env",
    "id_rsa",
    "private_key",
    "credentials.json",
    "kubeconfig",
    ".aws/credentials",
    ".ssh",
    "secrets",
    "passwords",
    "customer",
    "pii",
    "ssn",
    "prod database",
)


class SensitiveDataExposureCheck(Check):
    id = "MCP-021"
    title = "Sensitive data or file exposure"
    severity = Severity.HIGH
    default_capability = Capability.DATA_EXPOSURE
    owasp_mcp = "MCP10"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for resource in ctx.resources:
            text = f"{resource.uri} {resource.name or ''} {resource.description or ''}".lower()
            signal = _match_signal(text)
            if signal:
                findings.append(
                    self.finding(
                        target=resource.name or resource.uri,
                        evidence=f"Resource {resource.uri!r} appears to expose sensitive data or file signal {signal!r}.",
                        remediation="Remove sensitive resources from MCP exposure or gate them behind explicit authorization.",
                    )
                )
        for tool in ctx.tools:
            pieces = [tool.name, tool.description or ""]
            pieces.extend(value for _, value in iter_strings(tool.input_schema))
            signal = _match_signal(" ".join(pieces).lower())
            if signal:
                findings.append(
                    self.finding(
                        target=tool.name,
                        evidence=f"Tool {tool.name!r} appears to expose sensitive data or file signal {signal!r}.",
                        remediation="Restrict access to sensitive files and avoid exposing PII or secrets through MCP tools.",
                    )
                )
        return findings


def _match_signal(value: str) -> str | None:
    return next((signal for signal in SENSITIVE_SIGNALS if signal in value), None)
