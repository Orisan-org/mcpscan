"""Slice G of BRIEF-0.1.1.md: a connector failure must name the stage it failed at.

`Connection closed` covered three different failures with three different operator
responses: a command that never started, a process that started and died, and a process
that started and was still working when the timeout expired.

That collapsing has a cost on record. Bug 2 of this release was filed against
environment handling because `Connection closed` looked like a spawn failure; the
process had in fact started fine and was downloading a package. The bug was withdrawn.
These tests exist so the three stay distinguishable.
"""

from __future__ import annotations

import sys

from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.constants import EXIT_ENUMERATION

runner = CliRunner()


def _scan(command: str, timeout: str = "5") -> str:
    result = runner.invoke(app, ["scan", "--command", command, "--timeout", timeout])
    assert result.exit_code == EXIT_ENUMERATION, result.output
    return result.output


def test_spawn_failure_says_the_command_never_started() -> None:
    output = _scan("definitely-not-a-real-binary-xyz")

    assert "spawn stage" in output
    assert "never started" in output
    assert "definitely-not-a-real-binary-xyz" in output
    assert "No server code was executed" in output


def test_process_that_starts_and_dies_is_not_reported_as_a_spawn_failure() -> None:
    output = _scan(f"{sys.executable} -c \"print('not mcp')\"")

    assert "handshake stage" in output
    assert "started, then exited" in output
    assert "never started" not in output
    assert "not a missing executable and not a timeout" in output


def test_handshake_timeout_says_the_process_was_alive() -> None:
    output = _scan(f"{sys.executable} tests/fixtures/slow_server.py --delay 5", timeout="2")

    assert "handshake stage" in output
    assert "did not complete the MCP handshake within 2s" in output
    assert "was alive and had not answered" in output
    # The exact misreading that produced bug 2. The message now names it.
    assert "npx" in output and "downloading" in output


def test_the_three_stages_are_mutually_distinguishable() -> None:
    """The property that matters, asserted directly rather than implied by three tests.

    Any two of these producing the same text is the defect returning.
    """
    outputs = [
        _scan("definitely-not-a-real-binary-xyz"),
        _scan(f"{sys.executable} -c \"print('not mcp')\""),
        _scan(f"{sys.executable} tests/fixtures/slow_server.py --delay 5", timeout="2"),
    ]

    headlines = {line for output in outputs for line in output.splitlines() if "stage:" in line}
    assert len(headlines) == 3, f"stages collapsed into: {headlines}"


def test_every_failure_echoes_the_command() -> None:
    """Without the command, a scan-config run over several servers cannot be triaged."""
    for command, timeout in [
        ("definitely-not-a-real-binary-xyz", "5"),
        (f"{sys.executable} -c \"print('not mcp')\"", "5"),
        (f"{sys.executable} tests/fixtures/slow_server.py --delay 5", "2"),
    ]:
        output = _scan(command, timeout)
        assert "command:" in output, output
