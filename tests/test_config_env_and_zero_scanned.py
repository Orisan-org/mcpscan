"""Slice C of BRIEF-0.1.1.md: bugs 2 and 2b.

Bug 2b is real and fixed here: a grade was reported when nothing had been scanned.

Bug 2 is **withdrawn**: not reproducible, and not fixed. The reporter re-ran it in the
original environment with no code change and probed the child, which receives PATH and
HOME intact. See the brief. What is kept from it is the regression test it asked for —
a config with no `env` block must launch a server that needs PATH resolution — plus a
tightening the investigation did surface: the child environment is now mcpscan's own
decision rather than a property of whichever mcp SDK version got resolved.

The brief's prescribed fix, "inherit `os.environ`", is deliberately NOT implemented. It
would forward every secret the operator has exported into a server mcpscan runs
precisely because it may be hostile.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.config_scanner import _worst_grade
from mcpscan.connectors.stdio import INHERITED_ENV_VARS, child_environment
from mcpscan.constants import EXIT_ENUMERATION, EXIT_USAGE

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


def _write(tmp_path: Path, payload: dict) -> Path:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps(payload), encoding="utf-8")
    return config


# --------------------------------------------------------------- bug 2: child environment


def test_child_environment_carries_path_when_the_config_declares_no_env() -> None:
    """The brief's regression test: a config with no `env` block must still be able to
    launch a command that needs PATH resolution."""
    env = child_environment(None)

    assert "PATH" in env
    assert env["PATH"] == os.environ["PATH"]


def test_config_env_overlays_rather_than_replaces() -> None:
    env = child_environment({"API_TOKEN": "synthetic-secret-value"})

    assert env["API_TOKEN"] == "synthetic-secret-value"
    assert "PATH" in env, "a config env block must not cost the server its PATH"


def test_config_env_wins_on_conflict() -> None:
    env = child_environment({"PATH": "/only/this"})

    assert env["PATH"] == "/only/this"


def test_parent_secrets_are_not_forwarded_to_a_scanned_server(monkeypatch) -> None:
    """The brief said to inherit os.environ. That would hand the operator's credentials
    to a server mcpscan is running because it might be malicious."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "planted-parent-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "planted-parent-secret")

    env = child_environment(None)

    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "planted-parent-secret" not in json.dumps(env)
    assert set(env).issubset(set(INHERITED_ENV_VARS))


def test_scan_config_with_no_env_block_launches_through_path_resolution(tmp_path) -> None:
    """End to end, with a real stdio server found via PATH rather than an absolute path.

    Uses the repo's own fixture server through a bare interpreter name, so the child
    genuinely has to resolve it. This is the shape the brief asked for without needing
    npx and the network.
    """
    interpreter = Path(sys.executable)
    bin_dir = interpreter.parent
    config = _write(
        tmp_path,
        {
            "mcpServers": {
                "benign": {
                    "command": interpreter.name,
                    "args": [str(ROOT / "tests" / "fixtures" / "benign_server.py")],
                }
            }
        },
    )

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(
        [sys.executable, "-m", "mcpscan", "scan-config", str(config), "--yes"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env=env,
        timeout=180,
    )

    assert "1 scanned" in result.stdout, f"{result.stdout}\n{result.stderr}"
    assert "0 failed" in result.stdout


def test_planted_parent_secret_never_reaches_the_report(tmp_path, monkeypatch) -> None:
    """The redaction invariant, checked against an inherited value rather than a
    config-supplied one."""
    monkeypatch.setenv("ORISAN_TEST_PARENT_SECRET", "planted-parent-secret")
    config = _write(
        tmp_path,
        {
            "mcpServers": {
                "benign": {
                    "command": sys.executable,
                    "args": [str(ROOT / "tests" / "fixtures" / "benign_server.py")],
                    "env": {"API_TOKEN": "synthetic-config-secret"},
                }
            }
        },
    )
    report = tmp_path / "report.json"

    runner.invoke(
        app,
        ["scan-config", str(config), "--yes", "--output", "json", "--out", str(report)],
    )

    payload = report.read_text()
    assert "planted-parent-secret" not in payload
    assert "synthetic-config-secret" not in payload
    assert "API_TOKEN" in payload, "env names are reported; only values are withheld"


# ------------------------------------------------------- bug 2b: no grade, nothing scanned


def test_worst_grade_is_none_when_nothing_was_scanned() -> None:
    assert _worst_grade([]) is None
    assert _worst_grade(["A", "D", "B"]) == "D"


def test_all_failed_reports_no_grade_and_exits_non_zero(tmp_path) -> None:
    config = _write(
        tmp_path,
        {"mcpServers": {"broken": {"command": "definitely-not-a-real-binary", "args": []}}},
    )

    result = runner.invoke(app, ["scan-config", str(config), "--yes"])

    assert result.exit_code == EXIT_ENUMERATION
    assert "0 scanned" in result.output
    assert "Worst grade: A" not in result.output, "a grade over an empty result set is a lie"
    assert "not assessed" in result.output


def test_all_skipped_reports_no_grade_and_exits_non_zero(tmp_path) -> None:
    """An --only filter that matches nothing must not read as a clean run in CI."""
    config = _write(
        tmp_path,
        {
            "mcpServers": {
                "benign": {"command": sys.executable, "args": ["-c", "pass"]},
            }
        },
    )

    result = runner.invoke(app, ["scan-config", str(config), "--yes", "--only", "nope"])

    assert result.exit_code == EXIT_USAGE
    assert "0 scanned" in result.output
    assert "Worst grade: A" not in result.output
    assert "not assessed" in result.output


def test_zero_scanned_json_report_carries_null_not_a_grade(tmp_path) -> None:
    """Machine-readable consumers must see the absence, not a default."""
    config = _write(
        tmp_path,
        {"mcpServers": {"broken": {"command": "definitely-not-a-real-binary", "args": []}}},
    )
    report = tmp_path / "report.json"

    runner.invoke(
        app,
        ["scan-config", str(config), "--yes", "--output", "json", "--out", str(report)],
    )

    payload = json.loads(report.read_text())
    assert payload["config"]["servers_scanned"] == 0
    assert payload["summary"]["worst_grade"] is None
