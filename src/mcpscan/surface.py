from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from mcpscan.capabilities import Capability, owasp_reference
from mcpscan.errors import TargetError
from mcpscan.models import (
    Finding,
    LaunchSurface,
    ScanContext,
    Severity,
    SurfaceItem,
    SurfaceSnapshot,
)

#: 2 added the launch block. A snapshot from 1 has no launch data, so drift
#: against it must say the launch was not compared rather than report no change.
SURFACE_VERSION = 2


def build_launch_surface(ctx: ScanContext) -> LaunchSurface:
    command = ctx.target.command or []
    return LaunchSurface(
        command_sha256=_hash_text(command[0]) if command else None,
        args_sha256=_hash_json(command[1:]) if len(command) > 1 else None,
        argv_preview=list(command),
        env_names=sorted(ctx.target.env),
        transport=ctx.target.transport.value,
        url=ctx.target.url,
    )


def build_surface(ctx: ScanContext) -> SurfaceSnapshot:
    return SurfaceSnapshot(
        surface_version=SURFACE_VERSION,
        launch=build_launch_surface(ctx),
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
    findings.extend(compare_launch_surface(current, baseline))
    return findings


def compare_launch_surface(current: SurfaceSnapshot, baseline: SurfaceSnapshot) -> list[Finding]:
    """Drift in how the server is started.

    This is the case a tool-surface comparison structurally cannot see: every
    description identical, and the thing that runs replaced.
    """
    if baseline.surface_version < 2:
        # A pre-launch-block baseline holds no launch data. Reporting "no
        # change" would be a claim about something never recorded.
        return [
            _drift_finding(
                "launch",
                f"Baseline was captured at surface_version {baseline.surface_version}, which has no "
                "launch data, so the launch command was NOT compared. Re-capture the baseline to "
                "cover it.",
                severity=Severity.INFO,
            )
        ]

    old, new = baseline.launch, current.launch
    findings: list[Finding] = []

    if old.command_sha256 != new.command_sha256:
        findings.append(
            _drift_finding(
                "launch",
                f"Launch executable changed ({_argv_label(old.argv_preview, 0)} -> "
                f"{_argv_label(new.argv_preview, 0)}). A different program is being started.",
            )
        )
    if old.args_sha256 != new.args_sha256:
        findings.append(
            _drift_finding(
                "launch",
                f"Launch arguments changed ({_join(old.argv_preview[1:])} -> "
                f"{_join(new.argv_preview[1:])}). The same program is being started differently.",
            )
        )
    if sorted(old.env_names) != sorted(new.env_names):
        added = sorted(set(new.env_names) - set(old.env_names))
        removed = sorted(set(old.env_names) - set(new.env_names))
        parts = []
        if added:
            parts.append(f"added {', '.join(added)}")
        if removed:
            parts.append(f"removed {', '.join(removed)}")
        findings.append(
            _drift_finding(
                "launch",
                f"Configured environment variable names changed ({'; '.join(parts)}). "
                "Values are not compared and were not read.",
                severity=Severity.MEDIUM,
            )
        )
    if old.transport != new.transport:
        findings.append(
            _drift_finding("launch", f"Transport changed ({old.transport} -> {new.transport}).")
        )
    if old.url != new.url:
        findings.append(_drift_finding("launch", f"Remote URL changed ({old.url} -> {new.url})."))
    return findings


def _join(argv: list[str]) -> str:
    return " ".join(argv) if argv else "(none)"


def _argv_label(argv: list[str], index: int) -> str:
    return argv[index] if len(argv) > index else "(none)"


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


def _drift_finding(target: str, evidence: str, severity: Severity | None = None) -> Finding:
    return Finding(
        id="MCP-002",
        title="Tool definition drift",
        severity=severity or Severity.HIGH,
        capability=Capability.SURFACE_DRIFT,
        owasp_mcp="MCP03",
        target=target,
        evidence=evidence,
        remediation=(
            "Review the change before trusting this server again. A surface that changes after "
            "you approved it is the rug-pull shape: compare with `mcpscan drift`, and re-snapshot "
            "only once you have decided the change is legitimate."
        ),
        reference=owasp_reference("MCP03"),
        payload_stored=False,
    )


def _prefix(value: str | None) -> str:
    return value[:12] if value else "none"
