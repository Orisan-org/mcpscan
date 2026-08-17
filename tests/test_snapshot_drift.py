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
