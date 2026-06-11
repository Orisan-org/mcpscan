from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from mcpscan.capabilities import Capability, owasp_reference
from mcpscan.errors import TargetError
from mcpscan.models import Finding, ScanContext, Severity, SurfaceItem, SurfaceSnapshot

SURFACE_VERSION = 1


def build_surface(ctx: ScanContext) -> SurfaceSnapshot:
    return SurfaceSnapshot(
        surface_version=SURFACE_VERSION,
        tools=[
            SurfaceItem(
                name=tool.name,
                description_sha256=_hash_text(tool.description),
                schema_sha256=_hash_json(tool.input_schema),
            )
            for tool in sorted(ctx.tools, key=lambda item: item.name)
        ],
        resources=[
            SurfaceItem(
                name=resource.name or resource.uri,
                description_sha256=_hash_text(resource.description),
                schema_sha256=None,
            )
            for resource in sorted(ctx.resources, key=lambda item: item.name or item.uri)
        ],
        prompts=[
            SurfaceItem(
                name=prompt.name,
                description_sha256=_hash_text(prompt.description),
                schema_sha256=_hash_json(prompt.arguments),
            )
            for prompt in sorted(ctx.prompts, key=lambda item: item.name)
        ],
    )


def load_baseline_surface(path: Path) -> SurfaceSnapshot:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TargetError(f"Baseline file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TargetError(f"Baseline file is not valid JSON: {path}") from exc
    surface = payload.get("surface") if isinstance(payload, dict) else None
    if not isinstance(surface, dict):
        raise TargetError(f"Baseline report does not contain a surface block: {path}")
    try:
        return SurfaceSnapshot.model_validate(surface)
    except Exception as exc:
        raise TargetError(f"Baseline surface block is invalid: {path}") from exc


def compare_tool_surface(current: SurfaceSnapshot, baseline: SurfaceSnapshot) -> list[Finding]:
    current_tools = {item.name: item for item in current.tools}
    baseline_tools = {item.name: item for item in baseline.tools}
    findings: list[Finding] = []

    for name in sorted(current_tools.keys() - baseline_tools.keys()):
        findings.append(_drift_finding(name, f"Tool {name!r} was added since baseline."))
    for name in sorted(baseline_tools.keys() - current_tools.keys()):
        findings.append(_drift_finding(name, f"Tool {name!r} was removed since baseline."))
    for name in sorted(current_tools.keys() & baseline_tools.keys()):
        old = baseline_tools[name]
        new = current_tools[name]
        if old.description_sha256 != new.description_sha256:
            findings.append(
                _drift_finding(
                    name,
                    f"Tool {name!r} description hash changed "
                    f"({_prefix(old.description_sha256)} -> {_prefix(new.description_sha256)}).",
                )
            )
        if old.schema_sha256 != new.schema_sha256:
            findings.append(
                _drift_finding(
                    name,
                    f"Tool {name!r} schema hash changed "
                    f"({_prefix(old.schema_sha256)} -> {_prefix(new.schema_sha256)}).",
                )
            )
    return findings


def _hash_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"\s+", " ", value).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str | None:
    if value in ({}, [], None):
        return None
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _drift_finding(target: str, evidence: str) -> Finding:
    return Finding(
        id="MCP-002",
        title="Tool definition drift",
        severity=Severity.HIGH,
        capability=Capability.SURFACE_DRIFT,
        owasp_mcp="MCP03",
        target=target,
        evidence=evidence,
        remediation="Review the changed MCP tool surface before trusting this server again.",
        reference=owasp_reference("MCP03"),
        payload_stored=False,
    )


def _prefix(value: str | None) -> str:
    return value[:12] if value else "none"
