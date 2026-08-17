"""Slice 3 — replaying a stored surface, with nothing started.

This is what item 1 of the spec actually wanted: every check running, no
execution, CI-safe. A config file has no tool descriptions in it, so the only
way to run the description-based checks without starting the server is to have
captured the surface once.

The bar is that a replay finds exactly what a live scan of the same server
found. Anything less and the tier is a weaker scan wearing a full scan's
clothes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.snapshot import (
    PROFILE_FULL,
    PROFILE_HASHES,
    SnapshotProfileError,
    build_snapshot,
    load_snapshot,
    replay_context,
    replay_provenance,
    write_snapshot,
)

runner = CliRunner()
PYEXE = sys.executable
MALICIOUS = f"{PYEXE} tests/fixtures/malicious_server.py"


def _capture(path: Path, profile: str = PROFILE_FULL, command: str = MALICIOUS) -> None:
    result = runner.invoke(
        app,
        [
            "snapshot",
            "--command",
            command,
            "--out",
            str(path),
            "--profile",
            profile,
            "--label",
            "t",
        ],
    )
    assert result.exit_code == 0, result.output


def _ids(payload: dict) -> list[str]:
    return sorted(f"{f['id']}:{f['target']}" for f in payload["findings"])


# ------------------------------------------------------------ A3.1 parity with live


def test_replay_finds_exactly_what_a_live_scan_found(tmp_path: Path) -> None:
    live = json.loads(
        runner.invoke(app, ["scan", "--command", MALICIOUS, "--output", "json"]).stdout
    )
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    replayed = json.loads(
        runner.invoke(
            app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "json"]
        ).stdout
    )

    assert _ids(replayed) == _ids(live)
    assert replayed["tier"] == "surface"
    assert live["tier"] == "live"


def test_replay_covers_resources_and_prompts_not_only_tools(tmp_path: Path) -> None:
    """Replaying tools alone silently dropped two findings from the malicious
    fixture: a resource-derived one, and the lookalike check comparing the
    operator's label instead of the server's own reported name."""
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    ctx = replay_context(load_snapshot(snapshot), snapshot)
    assert ctx.resources, "resources must be rebuilt"
    assert ctx.server.name and ctx.server.name != "t", "the server's own name must survive"


# ------------------------------------------------------------ A3.2 nothing runs


def test_replay_starts_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("a replay must not start a process")

    monkeypatch.setattr(subprocess, "Popen", explode)
    result = runner.invoke(
        app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "json"]
    )
    assert json.loads(result.stdout)["findings"]


def test_replay_works_when_the_command_no_longer_exists(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    document = load_snapshot(snapshot)
    document["body"]["surface"]["launch"]["argv_preview"] = ["/gone/not-here"]
    write_snapshot(snapshot, document)
    result = runner.invoke(
        app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "json"]
    )
    assert json.loads(result.stdout)["findings"]


# ------------------------------------------------------------ A3.3 no silent degradation


def test_a_hashes_snapshot_is_refused_not_quietly_replayed(tmp_path: Path) -> None:
    """Hashes cannot be pattern-matched. Replaying them would run every check
    against empty text and report nothing found."""
    snapshot = tmp_path / "s.json"
    _capture(snapshot, profile=PROFILE_HASHES)
    with pytest.raises(SnapshotProfileError, match="hashes only"):
        replay_context(load_snapshot(snapshot), snapshot)

    result = runner.invoke(
        app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "json"]
    )
    assert result.exit_code == 2
    assert "profile full" in result.output


def test_tier_surface_without_a_snapshot_is_refused() -> None:
    result = runner.invoke(app, ["scan", "--tier", "surface", "--command", MALICIOUS])
    assert result.exit_code == 2
    assert "--from-snapshot" in result.output


def test_tier_live_contradicting_a_snapshot_is_refused(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    result = runner.invoke(app, ["scan", "--tier", "live", "--from-snapshot", str(snapshot)])
    assert result.exit_code == 2


def test_an_unknown_tier_is_refused() -> None:
    assert runner.invoke(app, ["scan", "--tier", "nonsense", "--command", MALICIOUS]).exit_code == 2


# ------------------------------------------------------------ staleness is visible


def test_the_report_names_the_snapshot_and_when_it_was_taken(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    payload = json.loads(
        runner.invoke(
            app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "json"]
        ).stdout
    )
    provenance = payload["replayed_from"]
    assert provenance["snapshot_path"] == str(snapshot)
    assert provenance["captured_at"]
    assert provenance["profile"] == PROFILE_FULL
    assert provenance["age_seconds"] is not None


def test_age_is_computed_from_the_capture_time(tmp_path: Path) -> None:
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat(timespec="seconds")
    document = build_snapshot(
        replay_context_stub(), label="t", profile=PROFILE_FULL, captured_at=old
    )
    provenance = replay_provenance(document, Path("s.json"))
    assert provenance["age_seconds"] > 29 * 86400
    assert provenance["age_human"] == "30d"


def replay_context_stub():
    from mcpscan.models import ScanContext, ScanTarget, TargetKind, Transport

    return ScanContext(
        target=ScanTarget(kind=TargetKind.COMMAND, transport=Transport.STDIO, command=["x"])
    )


def test_terminal_output_says_the_findings_are_as_captured(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    out = runner.invoke(
        app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--no-color"]
    ).stdout
    assert "Replayed from:" in out
    assert "AS CAPTURED, not as it is now" in out


def test_markdown_output_states_the_provenance(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    out = runner.invoke(
        app, ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "md"]
    ).stdout
    assert "Replayed from:" in out
    assert "as captured, not as it is now" in out


def test_a_snapshot_with_no_capture_time_is_refused(tmp_path: Path) -> None:
    """Inventing one would be exactly the staleness lie this prevents."""
    snapshot = tmp_path / "s.json"
    _capture(snapshot)
    document = load_snapshot(snapshot)
    document["envelope"].pop("captured_at")
    snapshot.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Exception, match="no capture time"):
        load_snapshot(snapshot)


# ------------------------------------------------------------ determinism


def test_replaying_the_same_snapshot_twice_is_identical(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    _capture(snapshot)

    def body() -> dict:
        payload = json.loads(
            runner.invoke(
                app,
                ["scan", "--tier", "surface", "--from-snapshot", str(snapshot), "--output", "json"],
            ).stdout
        )
        payload["scan"].pop("timestamp_utc", None)
        payload["replayed_from"].pop("age_seconds", None)
        payload["replayed_from"].pop("age_human", None)
        return payload

    assert body() == body()
