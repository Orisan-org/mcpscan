from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from mcpscan.adjudicate import adjudicate_findings
from mcpscan.checks.registry import active_checks
from mcpscan.engine import run_checks_with_coverage, sort_findings
from mcpscan.enumerator import enumerate_target
from mcpscan.models import (
    ExposedPrompt,
    ExposedResource,
    ExposedTool,
    PurposeCategory,
    ScanContext,
    ScanMetadata,
    ScanResult,
    ScanTarget,
)
from mcpscan.tiers import EvidenceTier
from mcpscan.purpose import build_purpose_profile
from mcpscan.scoring import count_findings, grade_for
from mcpscan.surface import build_surface, compare_tool_surface, load_baseline_surface


def config_context(target: ScanTarget) -> ScanContext:
    """A context built from the target alone. Nothing is started or contacted.

    There is no tool surface here and there cannot be one: descriptions live
    inside the server. Checks needing one are reported as not run.
    """
    return ScanContext(tier=EvidenceTier.CONFIG, target=target)


async def scan_target(
    target: ScanTarget,
    timeout_seconds: float = 20.0,
    baseline_path: Path | None = None,
    purpose_category: PurposeCategory | None = None,
    purpose_text: str | None = None,
    execute: bool = True,
) -> ScanResult:
    if execute:
        ctx = await enumerate_target(target, timeout_seconds=timeout_seconds)
    else:
        # No await, no subprocess, no socket. Asserted by a test that makes
        # both raise.
        ctx = config_context(target)
    return scan_context(
        ctx,
        baseline_path=baseline_path,
        purpose_category=purpose_category,
        purpose_text=purpose_text,
        timeout_seconds=timeout_seconds,
    )


def scan_context(
    ctx: ScanContext,
    baseline_path: Path | None = None,
    purpose_category: PurposeCategory | None = None,
    purpose_text: str | None = None,
    timeout_seconds: float | None = None,
) -> ScanResult:
    surface = build_surface(ctx)
    purpose_profile = build_purpose_profile(
        ctx, purpose_category=purpose_category, purpose_text=purpose_text
    )
    findings, checks_not_run = run_checks_with_coverage(ctx, active_checks())
    if baseline_path:
        findings.extend(compare_tool_surface(surface, load_baseline_surface(baseline_path)))
    findings = sort_findings(adjudicate_findings(findings, purpose_profile))
    return ScanResult(
        tier=ctx.tier,
        checks_not_run=[item.to_dict() for item in checks_not_run],
        target=ctx.target,
        server=ctx.server,
        findings=findings,
        counts=count_findings(findings),
        grade=grade_for(findings),
        surface=surface,
        purpose_profile=purpose_profile,
        scan=ScanMetadata(
            timeout_seconds=timeout_seconds,
            reproduce_command=_reproduce_command(ctx.target, timeout_seconds),
        ),
        warnings=ctx.warnings,
    )


def _reproduce_command(target: ScanTarget, timeout_seconds: float | None) -> str:
    pieces = ["mcpscan", "scan"]
    if target.command:
        pieces.extend(["--command", shlex.join(target.command)])
    elif target.url:
        pieces.append(target.url)
        pieces.extend(["--transport", target.transport.value])
    if timeout_seconds is not None:
        pieces.extend(["--timeout", str(timeout_seconds)])
    return shlex.join(pieces)


def normalize_tools(values: Any) -> list[ExposedTool]:
    return [normalize_tool(value) for value in values or []]


def normalize_resources(values: Any) -> list[ExposedResource]:
    return [normalize_resource(value) for value in values or []]


def normalize_prompts(values: Any) -> list[ExposedPrompt]:
    return [normalize_prompt(value) for value in values or []]


def normalize_tool(value: Any) -> ExposedTool:
    data = _to_dict(value)
    input_schema = data.get("inputSchema") or data.get("input_schema") or {}
    return ExposedTool(
        name=str(data.get("name") or "unknown"),
        description=data.get("description"),
        input_schema=input_schema if isinstance(input_schema, dict) else {},
        annotations=_dict_or_empty(data.get("annotations")),
        raw=_minimal_raw(
            data, ("name", "description", "inputSchema", "input_schema", "annotations")
        ),
    )


def normalize_resource(value: Any) -> ExposedResource:
    data = _to_dict(value)
    return ExposedResource(
        uri=str(data.get("uri") or "unknown"),
        name=data.get("name"),
        description=data.get("description"),
        mime_type=data.get("mimeType") or data.get("mime_type"),
        annotations=_dict_or_empty(data.get("annotations")),
        raw=_minimal_raw(
            data, ("uri", "name", "description", "mimeType", "mime_type", "annotations")
        ),
    )


def normalize_prompt(value: Any) -> ExposedPrompt:
    data = _to_dict(value)
    arguments = data.get("arguments") or []
    return ExposedPrompt(
        name=str(data.get("name") or "unknown"),
        description=data.get("description"),
        arguments=arguments if isinstance(arguments, list) else [],
        raw=_minimal_raw(data, ("name", "description", "arguments")),
    )


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _minimal_raw(data: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: data[key] for key in keys if key in data}


def _to_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, dict):
        return value
    return {
        key: getattr(value, key)
        for key in dir(value)
        if not key.startswith("_") and not callable(getattr(value, key))
    }
