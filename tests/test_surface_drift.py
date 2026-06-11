from __future__ import annotations

import json
import sys

from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.models import SurfaceItem, SurfaceSnapshot
from mcpscan.surface import compare_tool_surface

runner = CliRunner()


def test_scan_baseline_detects_tool_added_and_description_changed(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    first = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} tests/fixtures/benign_server.py",
            "--output",
            "json",
            "--out",
            str(baseline),
        ],
    )
    assert first.exit_code == 0

    second = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} tests/fixtures/benign_server_v2.py",
            "--baseline",
            str(baseline),
            "--output",
            "json",
            "--out",
            str(current),
        ],
    )
    assert second.exit_code == 1

    payload = json.loads(current.read_text(encoding="utf-8"))
    drift_findings = [finding for finding in payload["findings"] if finding["id"] == "MCP-002"]

    assert [finding["target"] for finding in drift_findings] == ["list_docs", "search_docs"]
    assert "was added" in drift_findings[0]["evidence"]
    assert "description hash changed" in drift_findings[1]["evidence"]
    assert "Search public documentation and release notes" not in json.dumps(payload)
    assert all(finding["payload_stored"] is False for finding in drift_findings)


def test_scan_baseline_against_same_report_has_no_drift(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    first = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} tests/fixtures/benign_server.py",
            "--output",
            "json",
            "--out",
            str(baseline),
        ],
    )
    assert first.exit_code == 0

    second = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} tests/fixtures/benign_server.py",
            "--baseline",
            str(baseline),
            "--output",
            "json",
            "--out",
            str(current),
        ],
    )
    assert second.exit_code == 0

    payload = json.loads(current.read_text(encoding="utf-8"))
    assert not [finding for finding in payload["findings"] if finding["id"] == "MCP-002"]


def test_scan_config_baseline_dir_writes_and_reads_per_server_baseline(tmp_path) -> None:
    baseline_dir = tmp_path / "baselines"
    first_config = tmp_path / "first.json"
    second_config = tmp_path / "second.json"
    first_config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {
                        "command": sys.executable,
                        "args": ["tests/fixtures/benign_server.py"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    second_config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {
                        "command": sys.executable,
                        "args": ["tests/fixtures/benign_server_v2.py"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    first = runner.invoke(
        app,
        ["scan-config", str(first_config), "--yes", "--baseline-dir", str(baseline_dir)],
    )
    assert first.exit_code == 0
    assert (baseline_dir / "docs.json").exists()

    second = runner.invoke(
        app,
        ["scan-config", str(second_config), "--yes", "--baseline-dir", str(baseline_dir)],
    )
    assert second.exit_code == 1
    assert "MCP-002" in second.output


def test_compare_tool_surface_detects_removed_and_schema_changed() -> None:
    baseline = SurfaceSnapshot(
        tools=[
            SurfaceItem(name="removed_tool", description_sha256="aaa", schema_sha256="bbb"),
            SurfaceItem(name="stable_tool", description_sha256="ccc", schema_sha256="old_schema"),
        ]
    )
    current = SurfaceSnapshot(
        tools=[
            SurfaceItem(name="stable_tool", description_sha256="ccc", schema_sha256="new_schema"),
        ]
    )

    findings = compare_tool_surface(current, baseline)

    assert [finding.target for finding in findings] == ["removed_tool", "stable_tool"]
    assert "was removed" in findings[0].evidence
    assert "schema hash changed" in findings[1].evidence
    assert all(finding.payload_stored is False for finding in findings)
