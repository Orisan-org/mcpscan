from __future__ import annotations

import subprocess
import sys

import pytest
from typer.testing import CliRunner

from mcpscan.cli import app

runner = CliRunner()


def test_stdio_benign_fixture_cli_scan() -> None:
    result = runner.invoke(
        app,
        ["scan", "--command", f"{sys.executable} tests/fixtures/benign_server.py"],
    )

    assert result.exit_code == 0
    assert "Grade: A" in result.output
    assert "No findings." in result.output


def test_stdio_malicious_fixture_cli_scan() -> None:
    result = runner.invoke(
        app,
        ["scan", "--command", f"{sys.executable} tests/fixtures/malicious_server.py"],
    )

    assert result.exit_code == 1
    assert "Grade: F" in result.output
    assert "MCP-010" in result.output


def test_stdio_timeout_message_is_clean() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} tests/fixtures/slow_server.py --delay 5",
            "--timeout",
            "2",
        ],
    )

    assert result.exit_code == 3
    # Slice G: the message must say which stage failed, and that the process was alive.
    assert "handshake stage" in result.output
    assert "did not complete the MCP handshake within 2s" in result.output
    assert "slow_server.py" in result.output, "the failing command must be echoed"
    assert "TaskGroup" not in result.output
    assert "ExceptionGroup" not in result.output


def test_stdio_slow_server_succeeds_with_larger_timeout() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} tests/fixtures/slow_server.py --delay 2",
            "--timeout",
            "30",
        ],
    )

    assert result.exit_code == 0
    assert "Grade: A" in result.output


def test_stdio_bad_process_error_unwraps_taskgroup() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--command",
            f"{sys.executable} -c \"print('not mcp')\"",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 3
    # Slice G: this process starts perfectly well and then fails to speak MCP. 0.1.0
    # reported it as "the command failed to start", which was a wrong diagnosis of the
    # wrong stage. The message must not claim a spawn failure here.
    assert "handshake stage" in result.output
    assert "started, then exited" in result.output
    assert "never started" not in result.output, (
        "this process starts perfectly well; 0.1.0 reported it as a spawn failure"
    )
    assert "TaskGroup" not in result.output
    assert "ExceptionGroup" not in result.output


@pytest.mark.network
def test_stdio_npx_filesystem_server_default_timeout() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcpscan",
            "scan",
            "--command",
            "npx -y @modelcontextprotocol/server-filesystem /tmp",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode in {0, 1}
    assert "TaskGroup" not in result.stdout
    assert "TaskGroup" not in result.stderr
