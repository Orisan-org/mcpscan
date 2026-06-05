from __future__ import annotations

from mcpscan.checks.base import Check
from mcpscan.models import Finding, ScanContext, Severity
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


class DangerousCapabilityExposureCheck(Check):
    id = "MCP-010"
    title = "Dangerous capability exposure"
    severity = Severity.HIGH
    reference = "OWASP MCP Top 10: Excessive permissions"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            haystack = _tool_haystack(tool.name, tool.description, tool.input_schema)
            matched = _match_class(haystack)
            if matched:
                findings.append(
                    self.finding(
                        target=tool.name,
                        evidence=f"Tool {tool.name!r} appears to expose {matched} based on name, description, or schema.",
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
