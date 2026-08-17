"""Slice 7 — snapshot and drift.

A rug pull is a change made after you approved a server, so a one-shot scan
structurally cannot see it. The case this exists for is the one a tool-surface
comparison misses entirely: every description byte-identical, and `uvx thing`
quietly replaced by `uvx thing --exfil`.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.models import ScanContext, ScanTarget, TargetKind, Transport
from mcpscan.snapshot import (
    SNAPSHOT_FORMAT,
    DriftMismatch,
    build_snapshot,
    compare_snapshots,
    load_snapshot,
    render_snapshot,
    write_snapshot,
)
from mcpscan.surface import SURFACE_VERSION, build_surface, compare_tool_surface

runner = CliRunner()
PYEXE = sys.executable
FIXTURE = f"{PYEXE} tests/fixtures/benign_server.py"
FIXTURE_V2 = f"{PYEXE} tests/fixtures/benign_server_v2.py"


def ctx(command: list[str], env: dict[str, str] | None = None) -> ScanContext:
    return ScanContext(
        target=ScanTarget(
            kind=TargetKind.COMMAND, transport=Transport.STDIO, command=command, env=env or {}
        )
    )


def snap(command: list[str], env: dict[str, str] | None = None, label: str = "t") -> dict:
    return build_snapshot(ctx(command, env), label=label)


# ------------------------------------------------------- the case that was invisible


def test_launch_argument_change_is_drift_with_identical_descriptions() -> None:
    changes = compare_snapshots(snap(["uvx", "thing"]), snap(["uvx", "thing", "--exfil"])).findings
    assert len(changes) == 1
    assert changes[0].target == "launch"
    assert "--exfil" in changes[0].evidence
    assert changes[0].severity.value == "high"


def test_launch_executable_change_is_drift() -> None:
    changes = compare_snapshots(snap(["uvx", "thing"]), snap(["node", "thing"])).findings
    assert any("executable changed" in c.evidence for c in changes)


def test_env_name_change_is_drift_and_values_are_never_compared() -> None:
    changes = compare_snapshots(
        snap(["node", "s.js"], {"A": "one"}), snap(["node", "s.js"], {"A": "two", "B": "x"})
    ).findings
    assert len(changes) == 1
    assert "added B" in changes[0].evidence
    # A's value changed from "one" to "two" and that is deliberately invisible:
    # a hash of a secret is a guessing oracle.
    assert "one" not in changes[0].evidence and "two" not in changes[0].evidence


def test_no_change_is_no_drift() -> None:
    assert compare_snapshots(snap(["uvx", "thing"]), snap(["uvx", "thing"])).findings == []


# ------------------------------------------------------- the pre-existing dimensions


def test_tool_added_removed_and_description_changed() -> None:
    from mcpscan.models import ExposedTool

    base = ctx(["x"])
    base.tools = [ExposedTool(name="a", description="one", input_schema={})]
    after = ctx(["x"])
    after.tools = [
        ExposedTool(name="a", description="CHANGED", input_schema={}),
        ExposedTool(name="b", description="new", input_schema={}),
    ]
    evidence = " ".join(
        f.evidence for f in compare_tool_surface(build_surface(after), build_surface(base))
    )
    assert "'b' was added" in evidence
    assert "'a' description hash changed" in evidence

    gone = ctx(["x"])
    gone.tools = []
    assert "'a' was removed" in " ".join(
        f.evidence for f in compare_tool_surface(build_surface(gone), build_surface(base))
    )


# ------------------------------------------------------- refusals


def test_comparing_two_different_targets_is_refused() -> None:
    with pytest.raises(DriftMismatch):
        compare_snapshots(snap(["a"], label="one"), snap(["b"], label="two"))


def test_an_unknown_snapshot_format_is_refused_not_guessed(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    document = snap(["uvx", "thing"])
    document["snapshot_format"] = 99
    path.write_text(render_snapshot(document), encoding="utf-8")
    with pytest.raises(Exception, match="format 99"):
        load_snapshot(path)


def test_a_pre_launch_baseline_says_the_launch_was_not_compared() -> None:
    """Silence would be a claim about something never recorded."""
    old = snap(["uvx", "thing"])
    old["body"]["surface"]["surface_version"] = 1
    old["body"]["surface"].pop("launch", None)
    changes = compare_snapshots(old, snap(["uvx", "COMPLETELY-DIFFERENT"])).findings
    assert any("was NOT compared" in c.evidence for c in changes)
    assert all(c.severity.value == "info" for c in changes if "NOT compared" in c.evidence)


# ------------------------------------------------------- the file itself


def test_snapshot_bodies_are_byte_identical_for_an_unchanged_server() -> None:
    """So they can be committed and diffed.

    The BODY is timestamp-free, not the whole document: format 2 moved the
    capture time into an envelope so a replay can state how old its evidence
    is. Both properties hold at once because drift compares bodies.
    """
    from mcpscan.snapshot import canonical_body

    assert canonical_body(snap(["uvx", "thing"])) == canonical_body(snap(["uvx", "thing"]))


def test_the_envelope_carries_a_capture_time_and_the_body_does_not() -> None:
    document = snap(["uvx", "thing"])
    assert document["envelope"]["captured_at"]
    assert "captured_at" not in json.dumps(document["body"])


def test_a_snapshot_carries_the_ruleset_and_surface_versions() -> None:
    document = snap(["uvx", "thing"])
    assert document["snapshot_format"] == SNAPSHOT_FORMAT
    assert document["body"]["surface_version"] == SURFACE_VERSION
    assert len(document["body"]["ruleset_digest"]) == 64


def test_write_is_atomic_under_a_kill(tmp_path: Path) -> None:
    """A truncated baseline reports drift against reality forever."""
    path = tmp_path / "snap.json"
    write_snapshot(path, snap(["uvx", "thing"]))
    good = path.read_text(encoding="utf-8")

    script = tmp_path / "writer.py"
    script.write_text(
        "import sys, time\n"
        f"sys.path.insert(0, {str(Path.cwd() / 'src')!r})\n"
        "from pathlib import Path\n"
        "from mcpscan.snapshot import write_snapshot\n"
        "import mcpscan.snapshot as s\n"
        "orig = s.render_snapshot\n"
        "def slow(doc):\n"
        "    out = orig(doc)\n"
        "    time.sleep(5)\n"
        "    return out\n"
        "s.render_snapshot = slow\n"
        "print('go', flush=True)\n"
        f"write_snapshot(Path({str(path)!r}), {{'snapshot_format': 2, 'body': {{}}, 'envelope': {{}}}})\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        [PYEXE, str(script)], stdout=subprocess.PIPE, text=True, start_new_session=True
    )
    assert proc.stdout is not None
    proc.stdout.readline()
    time.sleep(0.4)
    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    proc.wait(timeout=10)

    # The property that matters: either the old content or the new one, never
    # a partial file.
    assert path.read_text(encoding="utf-8") == good

    # SIGKILL runs no handler, so the temp file survives. That is unavoidable;
    # what must not happen is that it accumulates forever.
    strays = [p for p in tmp_path.iterdir() if p.name.startswith(".snap.json.")]
    assert len(strays) == 1
    os.utime(strays[0], (0, 0))  # age it past the sweep threshold
    write_snapshot(path, snap(["uvx", "thing"]))
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".snap.json.")]


def test_a_fresh_temp_file_is_not_swept(tmp_path: Path) -> None:
    """A concurrent writer's in-flight temp must survive another writer's sweep."""
    path = tmp_path / "snap.json"
    inflight = tmp_path / ".snap.json.inflight.tmp"
    inflight.write_text("partial", encoding="utf-8")
    write_snapshot(path, snap(["uvx", "thing"]))
    assert inflight.exists()


# ------------------------------------------------------- the commands


def test_snapshot_then_drift_against_a_real_server(tmp_path: Path) -> None:
    out = tmp_path / "a.json"
    first = runner.invoke(
        app, ["snapshot", "--command", FIXTURE, "--out", str(out), "--label", "demo"]
    )
    assert first.exit_code == 0, first.output

    clean = runner.invoke(app, ["drift", "--baseline", str(out), "--command", FIXTURE])
    assert clean.exit_code == 0
    assert "No drift" in clean.stdout


def test_drift_exit_codes_are_the_contract(tmp_path: Path) -> None:
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    write_snapshot(a, snap(["uvx", "thing"], label="demo"))
    write_snapshot(b, snap(["uvx", "thing", "--exfil"], label="demo"))

    assert runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(a)]).exit_code == 0
    assert runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)]).exit_code == 1

    other = tmp_path / "c.json"
    write_snapshot(other, snap(["uvx", "thing"], label="elsewhere"))
    mismatch = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(other)])
    assert mismatch.exit_code == 2
    assert "refusing to report that as drift" in mismatch.output


def test_drift_against_snapshots_executes_nothing(tmp_path: Path, monkeypatch) -> None:
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    write_snapshot(a, snap(["uvx", "thing"], label="demo"))
    write_snapshot(b, snap(["uvx", "thing", "--exfil"], label="demo"))

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("comparing two snapshots must not start anything")

    monkeypatch.setattr(subprocess, "Popen", explode)
    result = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)])
    assert result.exit_code == 1


def test_drift_json_output(tmp_path: Path) -> None:
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    write_snapshot(a, snap(["uvx", "thing"], label="demo"))
    write_snapshot(b, snap(["uvx", "thing", "--exfil"], label="demo"))
    out = runner.invoke(
        app, ["drift", "--baseline", str(a), "--against", str(b), "--output", "json"]
    )
    payload = json.loads(out.stdout)
    assert payload["drift_detected"] is True
    assert payload["baseline_label"] == "demo"
    assert payload["changes"][0]["target"] == "launch"


def test_snapshot_no_execute_records_the_launch_surface(tmp_path: Path) -> None:
    out = tmp_path / "a.json"
    result = runner.invoke(
        app,
        [
            "snapshot",
            "--command",
            "/nonexistent/not-here --flag",
            "--out",
            str(out),
            "--no-execute",
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["body"]["tier"] == "config"
    assert document["body"]["surface"]["launch"]["argv_preview"] == [
        "/nonexistent/not-here",
        "--flag",
    ]
    assert document["body"]["surface"]["tools"] == []


def test_a_missing_baseline_is_cannot_compare_not_a_crash(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "drift",
            "--baseline",
            str(tmp_path / "nope.json"),
            "--against",
            str(tmp_path / "nope.json"),
        ],
    )
    assert result.exit_code == 2


def test_an_unknown_profile_is_refused_not_silently_downgraded(tmp_path: Path) -> None:
    """`--profile fulll` used to write a hashes-only snapshot and exit 0. The
    mistake surfaced later at `scan --tier surface`, by which time the server
    may not be around to re-snapshot."""
    out = tmp_path / "s.json"
    result = runner.invoke(
        app,
        ["snapshot", "--command", FIXTURE, "--out", str(out), "--profile", "fulll", "--no-execute"],
    )
    assert result.exit_code == 2
    assert "--profile must be" in result.output
    assert not out.exists(), "nothing should be written for an invalid profile"


# ------------------------------------------------- reporting, not just exit codes
#
# Both defects below shipped in 0.2.0 and neither was caught, because every
# drift test asserted an exit code and none asserted what the command SAID,
# and because every test built both snapshots at the same tier so a mismatch
# never arose. These build them at different tiers on purpose.


def _snapshot_at(tmp_path: Path, name: str, command: str, *, live: bool, label: str = "t") -> Path:
    out = tmp_path / name
    args = ["snapshot", "--command", command, "--out", str(out), "--label", label]
    if not live:
        args.append("--no-execute")
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return out


def test_drift_names_the_label_and_capture_time_when_it_finds_drift(tmp_path: Path) -> None:
    """It printed "label None" for a snapshot labelled 't': the format-2 split
    moved `label` into the body and only the no-drift branch followed it."""
    a = _snapshot_at(tmp_path, "a.json", FIXTURE, live=True)
    b = _snapshot_at(tmp_path, "b.json", f"{FIXTURE} --exfil", live=True)
    out = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)])
    assert "label 't'" in out.stdout
    assert "label None" not in out.stdout
    assert "captured 20" in out.stdout


def test_the_no_drift_and_drift_messages_report_the_same_facts(tmp_path: Path) -> None:
    a = _snapshot_at(tmp_path, "a.json", FIXTURE, live=True)
    b = _snapshot_at(tmp_path, "b.json", f"{FIXTURE} --exfil", live=True)
    clean = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(a)]).stdout
    dirty = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)]).stdout
    for text in (clean, dirty):
        assert "label 't'" in text
        assert "captured 20" in text


def test_a_live_baseline_against_a_config_snapshot_reports_no_removed_tools(tmp_path: Path) -> None:
    """The 0.2.0 defect: nine tools reported "removed since baseline" against a
    snapshot that never captured a tool surface."""
    live = _snapshot_at(tmp_path, "live.json", FIXTURE, live=True)
    config = _snapshot_at(tmp_path, "cfg.json", f"{FIXTURE} --exfil", live=False)

    out = runner.invoke(app, ["drift", "--baseline", str(live), "--against", str(config)])
    assert "was removed since baseline" not in out.output
    # The launch change is comparable across tiers and must still be reported.
    assert "Launch arguments changed" in out.stdout
    assert "--exfil" in out.stdout
    assert out.exit_code == 1, "a real launch change is drift, whatever the surface state"


def test_the_refusal_says_which_side_lacked_a_surface(tmp_path: Path) -> None:
    live = _snapshot_at(tmp_path, "live.json", FIXTURE, live=True)
    config = _snapshot_at(tmp_path, "cfg.json", FIXTURE, live=False)

    out = runner.invoke(app, ["drift", "--baseline", str(live), "--against", str(config)])
    assert "CANNOT FULLY COMPARE" in out.output
    assert "tool surface was NOT compared" in out.output
    assert "the current snapshot was captured at config tier" in out.output
    assert "tiers differ (baseline live, current config)" in out.output

    reversed_out = runner.invoke(app, ["drift", "--baseline", str(config), "--against", str(live)])
    assert "the baseline snapshot was captured at config tier" in reversed_out.output


def test_two_config_snapshots_are_not_described_as_differing_tiers(tmp_path: Path) -> None:
    """They match each other and still have nothing to compare. Claiming a
    difference that is not there is its own small untruth."""
    a = _snapshot_at(tmp_path, "a.json", FIXTURE, live=False)
    b = _snapshot_at(tmp_path, "b.json", FIXTURE, live=False)
    out = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)])
    assert "both snapshots are config tier" in out.output
    assert "tiers differ" not in out.output


def test_an_uncompared_surface_is_never_reported_as_no_drift(tmp_path: Path) -> None:
    """Exit 2, not 0. "No drift" would be a claim about something never looked at."""
    a = _snapshot_at(tmp_path, "a.json", FIXTURE, live=False)
    b = _snapshot_at(tmp_path, "b.json", FIXTURE, live=False)
    out = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)])
    assert out.exit_code == 2
    assert "No drift" not in out.stdout


def test_json_output_states_whether_the_surface_was_compared(tmp_path: Path) -> None:
    live = _snapshot_at(tmp_path, "live.json", FIXTURE, live=True)
    config = _snapshot_at(tmp_path, "cfg.json", FIXTURE, live=False)

    mixed = json.loads(
        runner.invoke(
            app, ["drift", "--baseline", str(live), "--against", str(config), "--output", "json"]
        ).stdout
    )
    assert mixed["surface_compared"] is False
    assert "config tier" in mixed["surface_not_compared_reason"]

    same = json.loads(
        runner.invoke(
            app, ["drift", "--baseline", str(live), "--against", str(live), "--output", "json"]
        ).stdout
    )
    assert same["surface_compared"] is True
    assert same["surface_not_compared_reason"] is None


def test_matched_tiers_still_compare_the_tool_surface(tmp_path: Path) -> None:
    """The refusal must not have disabled the comparison it exists to protect."""
    a = _snapshot_at(tmp_path, "a.json", FIXTURE, live=True)
    b = _snapshot_at(tmp_path, "b.json", FIXTURE_V2, live=True)
    out = runner.invoke(app, ["drift", "--baseline", str(a), "--against", str(b)])
    assert "was added since baseline" in out.stdout or "description hash changed" in out.stdout
    assert out.exit_code == 1
