from __future__ import annotations

from typing import Any

from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity

SINK_WORDS = ("command", "shell", "query", "eval", "script", "execute", "run")
DANGEROUS_PARAM_NAMES = {"command", "cmd", "script", "code", "expression", "query", "path", "url"}
CONSTRAINT_KEYS = {"enum", "pattern", "maxLength", "format", "const"}


class CommandInjectionSurfaceCheck(Check):
    id = "MCP-030"
    title = "Command or code injection surface"
    severity = Severity.HIGH
    reference = "OWASP MCP Top 10: Injection"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            description = f"{tool.name} {tool.description or ''}".lower()
            if not any(word in description for word in SINK_WORDS):
                continue
            for param_name, schema in _iter_properties(tool.input_schema):
                if param_name.lower() not in DANGEROUS_PARAM_NAMES:
                    continue
                if schema.get("type") != "string":
                    continue
                severity = Severity.MEDIUM if _has_constraints(schema) else Severity.HIGH
                if severity == Severity.MEDIUM and param_name.lower() == "query":
                    continue
                findings.append(
                    self.finding(
                        severity=severity,
                        target=tool.name,
                        evidence=f"Tool {tool.name!r} accepts {'constrained' if severity == Severity.MEDIUM else 'unconstrained'} string parameter {param_name!r} and appears to execute commands, code, or queries.",
                        remediation="Constrain executable inputs with enums, patterns, length limits, allowlists, and server-side validation.",
                    )
                )
        return findings


def _iter_properties(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return [(key, value) for key, value in properties.items() if isinstance(value, dict)]
    return []


def _has_constraints(schema: dict[str, Any]) -> bool:
    return any(key in schema for key in CONSTRAINT_KEYS)
