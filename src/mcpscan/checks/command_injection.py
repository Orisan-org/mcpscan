from __future__ import annotations

import re
from typing import Any

from mcpscan.capabilities import Capability
from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity

EXECUTION_WORDS = (
    "bash",
    "command",
    "exec",
    "execute",
    "eval",
    "interpreter",
    "powershell",
    "python",
    "run",
    "script",
    "shell",
    "subprocess",
    "terminal",
)
EXECUTION_PARAM_NAMES = {"command", "cmd", "script", "code", "expression", "path", "url"}
SQL_WORDS = ("database", "db", "mysql", "postgres", "postgresql", "sql", "sqlite")
SQL_PARAM_NAMES = {"query", "sql", "statement"}
CONSTRAINT_KEYS = {"enum", "pattern", "maxLength", "format", "const"}


class CommandInjectionSurfaceCheck(Check):
    id = "MCP-030"
    title = "Command or code injection surface"
    severity = Severity.HIGH
    default_capability = Capability.SHELL_EXEC
    owasp_mcp = "MCP05"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            text = f"{tool.name} {tool.description or ''}".lower()
            for param_name, schema in _iter_properties(tool.input_schema):
                param = param_name.lower()
                sink = _sink(text, param)
                if sink is None:
                    continue
                sink_kind, capability = sink
                if schema.get("type") != "string":
                    continue
                severity = Severity.MEDIUM if _has_constraints(schema) else Severity.HIGH
                findings.append(
                    self.finding(
                        severity=severity,
                        capability=capability,
                        target=tool.name,
                        evidence=(
                            f"Tool {tool.name!r} accepts "
                            f"{'constrained' if severity == Severity.MEDIUM else 'unconstrained'} "
                            f"string parameter {param_name!r} and appears to execute {sink_kind}."
                        ),
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


def _sink(text: str, param_name: str) -> tuple[str, Capability] | None:
    if _has_sql_execution_semantics(text, param_name):
        return "SQL or database queries", Capability.CODE_EVAL
    if _has_command_or_code_execution_semantics(text, param_name):
        return "commands or code", _command_or_code_capability(text, param_name)
    return None


def _has_command_or_code_execution_semantics(text: str, param_name: str) -> bool:
    if param_name not in EXECUTION_PARAM_NAMES:
        return False
    tokens = _tokens(text)
    return any(word in tokens for word in EXECUTION_WORDS)


def _command_or_code_capability(text: str, param_name: str) -> Capability:
    tokens = _tokens(text)
    if param_name in {"code", "expression", "script"}:
        return Capability.CODE_EVAL
    if any(word in tokens for word in {"eval", "interpreter", "javascript", "python", "script"}):
        return Capability.CODE_EVAL
    return Capability.SHELL_EXEC


def _has_sql_execution_semantics(text: str, param_name: str) -> bool:
    if param_name not in SQL_PARAM_NAMES:
        return False
    tokens = _tokens(text)
    has_sql_context = any(word in tokens for word in SQL_WORDS)
    has_execution_context = any(
        word in tokens for word in ("execute", "exec", "run", "database", "db")
    )
    return has_sql_context and has_execution_context


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))
