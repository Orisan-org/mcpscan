from __future__ import annotations

import json
import sys

import pytest

from mcpscan.config_scanner import scan_mcp_configs


def write_config(tmp_path, payload: dict):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_config_scan_continues_after_failure_and_preserves_payload_contract(tmp_path) -> None:
    path = write_config(
        tmp_path,
        {
            "mcpServers": {
                "bad": {"command": sys.executable, "args": ["-c", "raise SystemExit(1)"]},
                "benign": {
                    "command": sys.executable,
                    "args": ["tests/fixtures/benign_server.py"],
                },
                "malicious": {
                    "command": sys.executable,
                    "args": ["tests/fixtures/malicious_server.py"],
                    "env": {"SECRET": "hunter2"},
                },
            }
        },
    )

    result = await scan_mcp_configs(path, consent=lambda server: True)

    assert result.summary.servers_total == 3
    assert result.summary.servers_scanned == 2
    assert result.summary.servers_failed == 1
    assert {server.name for server in result.server_results} == {"benign", "malicious"}
    findings = [finding for server in result.server_results for finding in server.result.findings]
    assert findings
    assert all(finding.payload_stored is False for finding in findings)
    assert "hunter2" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_config_scan_declined_stdio_is_skipped(tmp_path) -> None:
    path = write_config(
        tmp_path,
        {
            "mcpServers": {
                "benign": {"command": sys.executable, "args": ["tests/fixtures/benign_server.py"]}
            }
        },
    )

    result = await scan_mcp_configs(path, consent=lambda server: False)

    assert result.summary.servers_scanned == 0
    assert result.summary.servers_skipped == 1
    assert result.skipped[0].reason == "no consent"


@pytest.mark.asyncio
async def test_config_scan_only_filters_server_names(tmp_path) -> None:
    path = write_config(
        tmp_path,
        {
            "mcpServers": {
                "benign": {
                    "command": sys.executable,
                    "args": ["tests/fixtures/benign_server.py"],
                },
                "malicious": {
                    "command": sys.executable,
                    "args": ["tests/fixtures/malicious_server.py"],
                },
            }
        },
    )

    result = await scan_mcp_configs(path, only={"benign"}, consent=lambda server: True)

    assert [server.name for server in result.server_results] == ["benign"]
    assert [server.name for server in result.skipped] == ["malicious"]


@pytest.mark.asyncio
async def test_config_scan_all_failed_servers_records_failures(tmp_path) -> None:
    path = write_config(
        tmp_path,
        {"mcpServers": {"bad": {"command": sys.executable, "args": ["-c", "raise SystemExit(1)"]}}},
    )

    result = await scan_mcp_configs(path, consent=lambda server: True)

    assert result.summary.servers_scanned == 0
    assert result.summary.servers_failed == 1
