from __future__ import annotations

import re
from collections.abc import Iterable
from typing import NamedTuple

from mcpscan.capabilities import Capability
from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity
from mcpscan.utils.redact import redact_secret
from mcpscan.utils.text import iter_strings


class SecretMatch(NamedTuple):
    label: str
    value: str


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.I)),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "database URL with credentials",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s]+@[^/\s]+", re.I),
    ),
    (
        "assigned secret",
        re.compile(r"\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?([^'\"\s]{12,})", re.I),
    ),
)


class SecretExposureInMetadataCheck(Check):
    id = "MCP-020"
    title = "Secret exposure in metadata"
    severity = Severity.CRITICAL
    default_capability = Capability.CREDENTIAL_ACCESS
    owasp_mcp = "MCP01"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target, location, value in _iter_metadata(ctx):
            for match in _find_secret(value):
                findings.append(
                    self.finding(
                        target=target,
                        evidence=f"Potential {match.label} found in {location} and was redacted ({redact_secret(match.value)}).",
                        remediation="Remove secrets from MCP metadata and pass credentials through secure runtime configuration.",
                    )
                )
                break
        return findings


def _find_secret(value: str) -> Iterable[SecretMatch]:
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(value):
            matched_value = (
                match.group(1) if label == "assigned secret" and match.groups() else match.group(0)
            )
            yield SecretMatch(label, matched_value)


def _iter_metadata(ctx: ScanContext) -> Iterable[tuple[str, str, str]]:
    for path, value in iter_strings(ctx.server.model_dump()):
        yield "server", f"server metadata at {path}", value
    for tool in ctx.tools:
        for path, value in iter_strings(_without_raw(tool.model_dump())):
            yield tool.name, f"tool metadata for {tool.name!r} at {path}", value
    for resource in ctx.resources:
        for path, value in iter_strings(_without_raw(resource.model_dump())):
            yield resource.name or resource.uri, f"resource metadata at {path}", value
    for prompt in ctx.prompts:
        for path, value in iter_strings(_without_raw(prompt.model_dump())):
            yield prompt.name, f"prompt metadata for {prompt.name!r} at {path}", value


def _without_raw(value: dict) -> dict:
    copy = dict(value)
    copy.pop("raw", None)
    return copy
