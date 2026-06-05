from __future__ import annotations

import re
from collections.abc import Iterable

from mcpscan.checks.base import Check
from mcpscan.models import (
    ExposedPrompt,
    ExposedResource,
    ExposedTool,
    Finding,
    ScanContext,
    Severity,
)
from mcpscan.utils.text import iter_strings
from mcpscan.utils.unicode import contains_zero_width

PHRASES = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous",
    "system prompt",
    "developer message",
    "you are now",
    "you must call",
    "you must use",
    "do not tell the user",
    "hidden instruction",
    "exfiltrate",
    "send credentials",
    "read .env",
    "read secrets",
    "use other tools",
    "call another tool",
)

BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")


class ToolDescriptionPromptInjectionCheck(Check):
    id = "MCP-001"
    title = "Tool description prompt injection"
    severity = Severity.HIGH
    reference = "OWASP MCP Top 10: Tool poisoning"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target, location, value in _iter_metadata_text(ctx):
            lowered = value.lower()
            for phrase in PHRASES:
                if phrase in lowered:
                    findings.append(
                        self.finding(
                            target=target,
                            evidence=f"{location} contains instruction-like phrase {phrase!r}.",
                            remediation="Remove embedded instructions from MCP metadata and treat descriptions as untrusted display text.",
                        )
                    )
                    break
            else:
                if contains_zero_width(value):
                    findings.append(
                        self.finding(
                            target=target,
                            evidence=f"{location} contains zero-width or hidden Unicode characters.",
                            remediation="Remove hidden Unicode from MCP metadata and review the description source.",
                        )
                    )
                elif BASE64_RE.search(value) and _has_instruction_context(lowered):
                    findings.append(
                        self.finding(
                            target=target,
                            evidence=f"{location} contains a long encoded-looking blob with instruction-like context.",
                            remediation="Remove encoded instructions from metadata and keep tool descriptions human-readable.",
                        )
                    )
        return findings


def _has_instruction_context(value: str) -> bool:
    return any(
        word in value for word in ("instruction", "prompt", "decode", "secret", "credential")
    )


def _iter_metadata_text(ctx: ScanContext) -> Iterable[tuple[str, str, str]]:
    for tool in ctx.tools:
        yield from _tool_text(tool)
    for resource in ctx.resources:
        yield from _resource_text(resource)
    for prompt in ctx.prompts:
        yield from _prompt_text(prompt)


def _tool_text(tool: ExposedTool) -> Iterable[tuple[str, str, str]]:
    if tool.description:
        yield tool.name, f"Description for tool {tool.name!r}", tool.description
    for path, value in iter_strings(tool.input_schema):
        if path.lower().endswith("description") or ".description" in path.lower():
            yield tool.name, f"Schema text for tool {tool.name!r} at {path}", value
    for path, value in iter_strings(tool.annotations):
        yield tool.name, f"Annotation for tool {tool.name!r} at {path}", value


def _resource_text(resource: ExposedResource) -> Iterable[tuple[str, str, str]]:
    target = resource.name or resource.uri
    if resource.description:
        yield target, f"Description for resource {target!r}", resource.description
    for path, value in iter_strings(resource.annotations):
        yield target, f"Annotation for resource {target!r} at {path}", value


def _prompt_text(prompt: ExposedPrompt) -> Iterable[tuple[str, str, str]]:
    if prompt.description:
        yield prompt.name, f"Description for prompt {prompt.name!r}", prompt.description
    for path, value in iter_strings(prompt.arguments):
        if path.lower().endswith("description") or ".description" in path.lower():
            yield prompt.name, f"Argument text for prompt {prompt.name!r} at {path}", value
