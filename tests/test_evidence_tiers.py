"""Slice 1 — every report says what it was able to look at.

The failure being prevented: a scan that never started the server runs the six
description-based checks against an empty tool list, finds nothing, and prints a
grade. Nothing about that output distinguishes "this server is clean" from "we
did not look". That is the same false-assurance shape the project already
guards against elsewhere, applied to coverage instead of findings.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan.checks.registry import active_checks
from mcpscan.cli import app
from mcpscan.engine import select_checks
from mcpscan.models import ScanContext, ScanTarget, TargetKind, Transport
from mcpscan.scanner import config_context, scan_context
from mcpscan.tiers import ALL_TIERS, SURFACE_TIERS, EvidenceTier, grade_label

runner = CliRunner()
FIXTURE = f"{sys.executable} tests/fixtures/benign_server.py"


def _ctx(tier: EvidenceTier, *, url: str | None = None) -> ScanContext:
    target = (
        ScanTarget(kind=TargetKind.URL, transport=Transport.HTTP, url=url)
        if url
        else ScanTarget(kind=TargetKind.COMMAND, transport=Transport.STDIO, command=["x"])
    )
    return ScanContext(tier=tier, target=target)


# --------------------------------------------------------------- A1.1 no execution


def test_no_execute_never_spawns_or_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    """The strongest form: make execution impossible and require success anyway."""

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("config tier must not start a process or open a socket")

    monkeypatch.setattr(subprocess, "Popen", explode)
    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)

    result = scan_context(config_context(_ctx(EvidenceTier.CONFIG).target))
    assert result.tier is EvidenceTier.CONFIG


def test_no_execute_cli_completes_against_a_command_that_does_not_exist() -> None:
    # If anything tried to run it, this would fail at the spawn stage.
    out = runner.invoke(
        app,
        [
            "scan",
            "--command",
            "/nonexistent/definitely-not-here",
            "--no-execute",
            "--output",
            "json",
        ],
    )
    assert out.exit_code == 0, out.output
    assert json.loads(out.stdout)["tier"] == "config"


# --------------------------------------------------------------- A1.2/A1.3 not-run reporting


def test_surface_checks_are_reported_not_run_at_config_tier() -> None:
    runnable, skipped = select_checks(_ctx(EvidenceTier.CONFIG), active_checks())
    skipped_ids = {item.check_id for item in skipped}
    assert {"MCP-001", "MCP-010", "MCP-020", "MCP-021", "MCP-030"} <= skipped_ids
    assert all(item.reason for item in skipped)
    assert any("tool surface" in item.reason for item in skipped)
    # MCP-041 reads the URL scheme from config, so it must still run.
    assert "MCP-041" in {check.id for check in runnable}


def test_nothing_is_skipped_at_live_tier() -> None:
    runnable, skipped = select_checks(_ctx(EvidenceTier.LIVE), active_checks())
    assert skipped == []
    assert len(runnable) == len(active_checks())


def test_live_only_check_is_skipped_at_surface_tier() -> None:
    _, skipped = select_checks(_ctx(EvidenceTier.SURFACE), active_checks())
    assert "MCP-040" in {item.check_id for item in skipped}


def test_a_check_that_cannot_run_is_never_silently_dropped() -> None:
    total = len(active_checks())
    for tier in EvidenceTier:
        runnable, skipped = select_checks(_ctx(tier), active_checks())
        assert len(runnable) + len(skipped) == total, tier


def test_skipped_entries_carry_their_owasp_category() -> None:
    # So OWASP coverage reporting can tell "no check" from "check did not run".
    _, skipped = select_checks(_ctx(EvidenceTier.CONFIG), active_checks())
    assert all(item.owasp_mcp for item in skipped)


# --------------------------------------------------------------- A1.4 the grade


def test_grade_is_withheld_when_any_check_did_not_run() -> None:
    label = grade_label("A", EvidenceTier.CONFIG, [{"check_id": "MCP-001"}])
    assert "not assessed" in label
    assert label.strip() != "A"


def test_grade_is_plain_when_everything_ran() -> None:
    assert grade_label("A", EvidenceTier.LIVE, []) == "A"


def test_config_tier_json_has_null_grade_not_an_A() -> None:
    """A machine reading `grade` alone must not receive a letter unearned."""
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", "--output", "json"])
    payload = json.loads(out.stdout)
    assert payload["verdict_summary"]["grade"] is None
    assert payload["verdict_summary"]["grade_assessed"] is False
    assert "did not run" in payload["verdict_summary"]["grade_withheld_reason"]


def test_live_tier_json_still_carries_a_grade() -> None:
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--output", "json"])
    payload = json.loads(out.stdout)
    assert payload["verdict_summary"]["grade_assessed"] is True
    assert payload["verdict_summary"]["grade"] in {"A", "B", "C", "D", "F"}


# --------------------------------------------------------------- A1.5/A1.6 every format


def test_json_states_the_tier_at_top_level() -> None:
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", "--output", "json"])
    payload = json.loads(out.stdout)
    assert payload["tier"] == "config"
    assert "not started" in payload["tier_description"]
    assert len(payload["checks_not_run"]) >= 5


def test_terminal_states_the_tier_and_lists_what_it_could_not_check() -> None:
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", "--no-color"])
    assert "Evidence: config only" in out.stdout
    assert "Not checked at this tier" in out.stdout
    assert "MCP-001" in out.stdout


def test_markdown_states_the_tier() -> None:
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", "--output", "md"])
    assert "Evidence tier: config" in out.stdout
    assert "Not checked at this tier" in out.stdout


def test_scan_config_reports_the_tier_per_server(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"remote": {"url": "http://example.invalid/mcp"}}}),
        encoding="utf-8",
    )
    out = runner.invoke(app, ["scan-config", str(config), "--no-execute", "--output", "json"])
    payload = json.loads(out.stdout)
    server = payload["server_results"][0]
    assert server["tier"] == "config"
    assert len(server["checks_not_run"]) >= 5


# --------------------------------------------------------------- config tier still finds things


def test_config_tier_finds_plaintext_http_with_nothing_running() -> None:
    out = runner.invoke(
        app, ["scan", "http://example.invalid/mcp", "--no-execute", "--output", "json"]
    )
    payload = json.loads(out.stdout)
    assert any(f["id"] == "MCP-041" for f in payload["findings"])


def test_config_tier_findings_are_deterministic() -> None:
    def body() -> dict:
        out = runner.invoke(
            app, ["scan", "http://example.invalid/mcp", "--no-execute", "--output", "json"]
        )
        payload = json.loads(out.stdout)
        payload["scan"].pop("timestamp_utc", None)
        return payload

    assert body() == body()


# --------------------------------------------------------------- the default is safe


def test_checks_default_to_requiring_a_surface() -> None:
    """A check written without thinking about tiers must be skipped, not run blind."""

    class Untagged:
        requires = SURFACE_TIERS

    from mcpscan.checks.base import Check

    assert Check.requires == SURFACE_TIERS
    assert EvidenceTier.CONFIG not in Check.requires
    assert Untagged.requires == SURFACE_TIERS


def test_every_active_check_declares_a_non_empty_tier_set() -> None:
    for check in active_checks():
        assert check.requires, check.id
        assert check.requires <= ALL_TIERS, check.id
