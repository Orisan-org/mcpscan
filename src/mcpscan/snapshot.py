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
from datetime import UTC, datetime
from pathlib import Path

from mcpscan import __version__
from mcpscan.errors import TargetError
from mcpscan.models import (
    ExposedPrompt,
    ExposedResource,
    ExposedTool,
    Finding,
    ScanContext,
    ScanTarget,
    ServerInfo,
    SurfaceSnapshot,
    TargetKind,
    TargetOrigin,
    Transport,
)
from mcpscan.ruleset import RULESET_VERSION, ruleset_digest
from mcpscan.surface import SURFACE_VERSION, build_surface, compare_tool_surface
from mcpscan.tiers import EvidenceTier

#: 2 split the document into an unsigned envelope and a byte-stable body, and
#: added the capture profile. Format 1 is refused rather than upgraded: it has
#: no capture time, and inventing one would be the staleness lie this exists to
#: prevent.
SNAPSHOT_FORMAT = 2

#: Retained profiles. `hashes` proves a surface did not change; `full` also
#: keeps the text, which is what replay pattern-matches against.
PROFILE_HASHES = "hashes"
PROFILE_FULL = "full"


def build_snapshot(
    ctx: ScanContext,
    *,
    label: str | None = None,
    profile: str = PROFILE_HASHES,
    captured_at: str | None = None,
) -> dict:
    """A snapshot document, split into envelope and body.

    The BODY is byte-stable — no timestamp, no paths — so two snapshots of an
    unchanged server are byte-identical and a snapshot can be committed and
    diffed like a lockfile. Drift compares bodies.

    The ENVELOPE holds the capture time. That has to be recorded somewhere:
    replaying a snapshot produces a report about the world as it was when the
    snapshot was taken, and a report that does not say when that was lets a
    stale snapshot pass for a current scan. Keeping it out of the body is what
    lets both properties hold at once.
    """
    surface = build_surface(ctx, full=profile == PROFILE_FULL)
    return {
        "snapshot_format": SNAPSHOT_FORMAT,
        "envelope": {
            "captured_at": captured_at or datetime.now(UTC).isoformat(timespec="seconds"),
            "mcpscan_version": __version__,
        },
        "body": {
            "surface_version": SURFACE_VERSION,
            "profile": profile,
            "ruleset_version": RULESET_VERSION,
            "ruleset_digest": ruleset_digest(),
            "label": label or _default_label(ctx),
            "tier": ctx.tier.value,
            # The server's own reported identity, which is what the lookalike
            # check compares. Replaying with only the operator's label made
            # MCP-050 compare the wrong string and silently miss.
            "server": {"name": ctx.server.name, "version": ctx.server.version},
            "surface": surface.model_dump(mode="json", exclude_none=profile != PROFILE_FULL),
        },
    }


def snapshot_body(document: dict) -> dict:
    return document["body"]


def canonical_body(document: dict) -> str:
    """The stable part, for diffing and for digesting."""
    return json.dumps(document["body"], sort_keys=True, separators=(",", ":"))


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
    body = payload.get("body")
    if not isinstance(body, dict) or not isinstance(body.get("surface"), dict):
        raise TargetError(f"Snapshot {path} has no surface block.")
    if not isinstance(payload.get("envelope"), dict) or not payload["envelope"].get("captured_at"):
        # Without a capture time a replay cannot say how old its evidence is.
        raise TargetError(f"Snapshot {path} has no capture time; re-capture it.")
    return payload


def snapshot_surface(document: dict) -> SurfaceSnapshot:
    return SurfaceSnapshot.model_validate(document["body"]["surface"])


class DriftMismatch(TargetError):
    """The two snapshots do not describe the same server."""


def compare_snapshots(baseline: dict, current: dict) -> list[Finding]:
    """Drift between two snapshot documents.

    Refuses when the labels differ: comparing two different servers would
    report every tool as added and every other as removed, which looks like a
    catastrophic finding and is actually operator error.
    """
    base_label = snapshot_body(baseline).get("label")
    current_label = snapshot_body(current).get("label")
    if base_label != current_label:
        raise DriftMismatch(
            f"Snapshots describe different targets ({base_label!r} vs "
            f"{current_label!r}); refusing to report that as drift."
        )
    return compare_tool_surface(snapshot_surface(current), snapshot_surface(baseline))


class SnapshotProfileError(TargetError):
    """A hashes-only snapshot was handed to something that needs the text."""


def replay_context(document: dict, path: Path) -> ScanContext:
    """Rebuild a scan context from a stored surface. Nothing is started.

    Refuses a `hashes` snapshot rather than replaying it into a quiet result:
    the checks would iterate tools whose descriptions are None, match nothing,
    and report a clean surface. That is the false-assurance shape this whole
    tier system exists to prevent, so it is an error with an instruction
    instead.
    """
    body = snapshot_body(document)
    profile = body.get("profile")
    if profile != PROFILE_FULL:
        raise SnapshotProfileError(
            f"Snapshot {path} was captured with profile {profile!r}, which stores hashes only. "
            "Hashes cannot be pattern-matched, so replaying it would run every check against "
            "empty text and report nothing found. Re-capture with `mcpscan snapshot --profile full`."
        )

    surface = snapshot_surface(document)
    launch = surface.launch
    command = list(launch.argv_preview)
    target = ScanTarget(
        raw=launch.url or (" ".join(command) if command else None),
        kind=TargetKind.URL if launch.url else TargetKind.COMMAND,
        transport=Transport(launch.transport) if launch.transport else Transport.STDIO,
        origin=TargetOrigin.CONFIG,
        command=command or None,
        url=launch.url,
    )
    return ScanContext(
        tier=EvidenceTier.SURFACE,
        target=target,
        server=ServerInfo(**(body.get("server") or {"name": body.get("label")})),
        tools=[
            ExposedTool(
                name=item.name,
                description=item.description,
                input_schema=item.input_schema or {},
            )
            for item in surface.tools
        ],
        resources=[
            ExposedResource(
                uri=item.uri or item.name,
                name=item.name,
                description=item.description,
                mime_type=item.mime_type,
            )
            for item in surface.resources
        ],
        prompts=[
            ExposedPrompt(
                name=item.name,
                description=item.description,
                arguments=item.arguments or [],
            )
            for item in surface.prompts
        ],
    )


def replay_provenance(document: dict, path: Path, now: datetime | None = None) -> dict:
    """Where this verdict's evidence came from, and how old it is."""
    captured_raw = document["envelope"]["captured_at"]
    body = snapshot_body(document)
    provenance = {
        "snapshot_path": str(path),
        "captured_at": captured_raw,
        "label": body.get("label"),
        "profile": body.get("profile"),
        "snapshot_ruleset_digest": body.get("ruleset_digest"),
        "captured_at_tier": body.get("tier"),
    }
    try:
        captured = datetime.fromisoformat(captured_raw)
    except ValueError:
        provenance["age_seconds"] = None
        provenance["age_note"] = (
            "capture time is unparseable; treat this evidence as of unknown age"
        )
        return provenance
    if captured.tzinfo is None:
        captured = captured.replace(tzinfo=UTC)
    age = (now or datetime.now(UTC)) - captured
    provenance["age_seconds"] = int(age.total_seconds())
    provenance["age_human"] = _humanise(age.total_seconds())
    return provenance


def _humanise(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    if seconds < 172800:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"
