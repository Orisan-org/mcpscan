"""Snapshot and drift as first-class operations.

Drift detection existed only as a side effect of a full scan, so checking
whether a server changed meant re-running everything — and against a live
server, meaning starting it. That is the wrong shape for the thing you want to
run on every CI build.

A snapshot file is written atomically and is byte-identical for an unchanged
server, so it can be committed to a repository and diffed like any other
lockfile.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from mcpscan import __version__
from mcpscan.errors import TargetError
from mcpscan.models import Finding, ScanContext, SurfaceSnapshot
from mcpscan.ruleset import RULESET_VERSION, ruleset_digest
from mcpscan.surface import SURFACE_VERSION, build_surface, compare_tool_surface

SNAPSHOT_FORMAT = 1


def build_snapshot(ctx: ScanContext, *, label: str | None = None) -> dict:
    """A snapshot document. No timestamp: it must be byte-stable for diffing."""
    surface = build_surface(ctx)
    return {
        "snapshot_format": SNAPSHOT_FORMAT,
        "surface_version": SURFACE_VERSION,
        "mcpscan_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "ruleset_digest": ruleset_digest(),
        "label": label or _default_label(ctx),
        "tier": ctx.tier.value,
        "surface": surface.model_dump(mode="json"),
    }


def _default_label(ctx: ScanContext) -> str:
    if ctx.target.url:
        return ctx.target.url
    command = ctx.target.command or []
    return command[0] if command else "mcp-target"


def render_snapshot(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


#: A temp file older than this was left by a process that died. A concurrent
#: writer's temp is seconds old, so sweeping at this age cannot race one.
_STALE_TEMP_SECONDS = 60


def _sweep_stale_temps(path: Path, now: float) -> None:
    """Remove temp files a killed writer could not clean up itself.

    SIGKILL runs no handler, so `write_snapshot`'s own cleanup cannot fire and
    a `.snap.json.XXXX.tmp` is left behind. The atomicity property survives —
    the real file is never partial — but the litter accumulates in a directory
    people commit, so the next writer clears it.
    """
    for candidate in path.parent.glob(f".{path.name}.*.tmp"):
        try:
            if now - candidate.stat().st_mtime > _STALE_TEMP_SECONDS:
                candidate.unlink(missing_ok=True)
        except OSError:
            # Someone else's file, or gone already. Never fail a write over cleanup.
            continue


def write_snapshot(path: Path, document: dict) -> None:
    """Write atomically.

    A snapshot half-written by a killed process is a baseline that reports
    drift against reality forever, which trains people to ignore drift.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    _sweep_stale_temps(path, time.time())
    handle, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(render_snapshot(document))
            file.flush()
            os.fsync(file.fileno())
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_snapshot(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TargetError(f"Snapshot does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TargetError(f"Snapshot is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise TargetError(f"Snapshot is not an object: {path}")

    fmt = payload.get("snapshot_format")
    if fmt != SNAPSHOT_FORMAT:
        # Refused, not best-effort parsed. Guessing at an unknown format is how
        # a comparison silently stops comparing something.
        raise TargetError(
            f"Snapshot {path} is format {fmt!r}; this build understands {SNAPSHOT_FORMAT}. Re-capture it."
        )
    if not isinstance(payload.get("surface"), dict):
        raise TargetError(f"Snapshot {path} has no surface block.")
    return payload


def snapshot_surface(document: dict) -> SurfaceSnapshot:
    return SurfaceSnapshot.model_validate(document["surface"])


class DriftMismatch(TargetError):
    """The two snapshots do not describe the same server."""


def compare_snapshots(baseline: dict, current: dict) -> list[Finding]:
    """Drift between two snapshot documents.

    Refuses when the labels differ: comparing two different servers would
    report every tool as added and every other as removed, which looks like a
    catastrophic finding and is actually operator error.
    """
    if baseline.get("label") != current.get("label"):
        raise DriftMismatch(
            f"Snapshots describe different targets ({baseline.get('label')!r} vs "
            f"{current.get('label')!r}); refusing to report that as drift."
        )
    return compare_tool_surface(snapshot_surface(current), snapshot_surface(baseline))
