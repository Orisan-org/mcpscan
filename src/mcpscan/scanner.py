from __future__ import annotations

from typing import Any

from mcpscan.checks.registry import active_checks
from mcpscan.engine import run_checks
from mcpscan.enumerator import enumerate_target
from mcpscan.models import (
    ExposedPrompt,
    ExposedResource,
    ExposedTool,
    ScanContext,
    ScanResult,
    ScanTarget,
)
from mcpscan.scoring import count_findings, grade_for


async def scan_target(target: ScanTarget, timeout_seconds: float = 20.0) -> ScanResult:
    ctx = await enumerate_target(target, timeout_seconds=timeout_seconds)
    return scan_context(ctx)


def scan_context(ctx: ScanContext) -> ScanResult:
    findings = run_checks(ctx, active_checks())
    return ScanResult(
        target=ctx.target,
        server=ctx.server,
        findings=findings,
        counts=count_findings(findings),
        grade=grade_for(findings),
        warnings=ctx.warnings,
    )


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
