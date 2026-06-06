from __future__ import annotations

from typing import Any

from mcpscan.checks.base import Check
from mcpscan.models import ExposedTool, Finding, ScanContext, Severity
from mcpscan.utils.text import iter_strings

DANGER_CLASSES: dict[str, tuple[str, ...]] = {
    "shell execution": (
        "shell",
        "command",
        "exec",
        "subprocess",
        "bash",
        "powershell",
        "terminal",
        "run_command",
    ),
    "file read": ("read_file", "get_file", "open_file", " cat ", "filesystem", "file path"),
    "file write": (
        "write_file",
        "save_file",
        "delete_file",
        "remove_file",
        "edit_file",
        "patch_file",
    ),
    "network egress": ("fetch_url", "http_request", "curl", "wget", "webhook"),
    "code evaluation": ("eval", "execute_python", "node_eval", "javascript", "interpreter"),
    "credential access": ("token", "api_key", "secret", "credential", "environment variable"),
}
NETWORK_ACTION_SIGNALS = (
    "browser navigate",
    "crawl",
    "download",
    "fetch",
    "fetches",
    "http",
    "internet",
    "navigate",
    "network",
    "outbound",
    "request",
    "scrape",
    "web",
)
URL_PARAM_NAMES = {"endpoint", "link", "target_url", "uri", "url", "website"}
NETWORK_CONSTRAINT_KEYS = {"const", "enum", "pattern"}


class DangerousCapabilityExposureCheck(Check):
    id = "MCP-010"
    title = "Dangerous capability exposure"
    severity = Severity.HIGH
    reference = "OWASP MCP Top 10: Excessive permissions"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            haystack = _tool_haystack(tool.name, tool.description, tool.input_schema)
            matched = _match_network_capability(tool, haystack)
            severity = matched[1] if matched else self.severity
            danger_class = matched[0] if matched else _match_class(haystack)
            if danger_class:
                findings.append(
                    self.finding(
                        severity=severity,
                        target=tool.name,
                        evidence=f"Tool {tool.name!r} appears to expose {danger_class} based on name, description, or schema.",
                        remediation="Restrict dangerous tools, require explicit approval, and scope parameters as narrowly as possible.",
                    )
                )
        for resource in ctx.resources:
            haystack = f"{resource.uri} {resource.name or ''} {resource.description or ''}".lower()
            matched = _match_class(haystack)
            if matched:
                findings.append(
                    self.finding(
                        target=resource.name or resource.uri,
                        evidence=f"Resource {resource.uri!r} appears related to {matched}.",
                        remediation="Avoid exposing broad filesystem, credential, or network-capable resources over MCP.",
                    )
                )
        return findings


def _tool_haystack(name: str, description: str | None, schema: dict) -> str:
    pieces = [name, description or ""]
    pieces.extend(name for name, _ in _iter_properties(schema))
    pieces.extend(value for _, value in iter_strings(schema))
    return " ".join(pieces).lower().replace("_", " ")


def _match_class(value: str) -> str | None:
    padded = f" {value} "
    normalized = value.replace(" ", "_")
    for danger_class, signals in DANGER_CLASSES.items():
        for signal in signals:
            if signal in padded or signal in normalized:
                return danger_class
    return None


def _match_network_capability(tool: ExposedTool, haystack: str) -> tuple[str, Severity] | None:
    padded = f" {haystack} "
    normalized = haystack.replace(" ", "_")

    has_network_action = any(signal in padded for signal in NETWORK_ACTION_SIGNALS)
    has_url_input = _has_url_input(tool.input_schema)
    has_strong_network_name = any(
        signal in normalized
        for signal in (
            "browser_navigate",
            "crawl",
            "download_file",
            "fetch_url",
            "http_request",
            "scrape_url",
            "web_request",
        )
    )

    if not (has_strong_network_name or (has_network_action and has_url_input)):
        return None

    severity = Severity.MEDIUM if _has_constrained_url_input(tool.input_schema) else Severity.HIGH
    return "outbound network request capability", severity


def _iter_properties(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return [(key, value) for key, value in properties.items() if isinstance(value, dict)]
    return []


def _has_url_input(schema: dict[str, Any]) -> bool:
    for name, property_schema in _iter_properties(schema):
        if name.lower() in URL_PARAM_NAMES:
            return True
        strings = " ".join(value for _, value in iter_strings(property_schema)).lower()
        if "url" in strings or "uri" in strings or "http://" in strings or "https://" in strings:
            return True
    return False


def _has_constrained_url_input(schema: dict[str, Any]) -> bool:
    for name, property_schema in _iter_properties(schema):
        if name.lower() in URL_PARAM_NAMES and any(
            key in property_schema for key in NETWORK_CONSTRAINT_KEYS
        ):
            return True
    return False
