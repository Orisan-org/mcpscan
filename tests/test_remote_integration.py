from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcpscan.errors import EnumerationError
from mcpscan.models import ScanTarget, TargetKind, Transport
from mcpscan.reporters.json_reporter import render_json
from mcpscan.scanner import scan_target

ROOT = Path(__file__).resolve().parents[1]
REMOTE_FIXTURE = ROOT / "tests" / "fixtures" / "remote_streamable_server.py"

pytestmark = pytest.mark.filterwarnings("ignore:Use `streamable_http_client` instead")


def test_streamable_http_remote_scan_enumerates_and_finds_risks() -> None:
    port = _free_port()
    process = _start_remote_fixture(port)
    try:
        _wait_for_port(port)
        result = asyncio.run(
            scan_target(
                ScanTarget(
                    raw=f"http://127.0.0.1:{port}/mcp",
                    kind=TargetKind.URL,
                    transport=Transport.HTTP,
                    url=f"http://127.0.0.1:{port}/mcp",
                ),
                timeout_seconds=5,
            )
        )
    finally:
        _stop_process(process)

    finding_ids = {finding.id for finding in result.findings}
    assert result.target.transport == Transport.HTTP
    assert result.server.name == "remote-risky-server"
    assert {finding.target for finding in result.findings if finding.id == "MCP-030"} == {
        "run_command"
    }
    assert {"MCP-001", "MCP-010", "MCP-021", "MCP-030", "MCP-040", "MCP-041"}.issubset(finding_ids)
    assert all(finding.payload_stored is False for finding in result.findings)

    payload = json.loads(render_json(result))
    assert all(finding["payload_stored"] is False for finding in payload["findings"])
    assert "not actually running" not in json.dumps(payload)
    assert "redacted" not in json.dumps(payload)


def test_remote_connection_failure_is_clear_and_fast() -> None:
    port = _free_port()
    target = ScanTarget(
        raw=f"http://127.0.0.1:{port}/mcp",
        kind=TargetKind.URL,
        transport=Transport.HTTP,
        url=f"http://127.0.0.1:{port}/mcp",
    )

    started = time.monotonic()
    with pytest.raises(EnumerationError, match="Failed to enumerate remote MCP server"):
        asyncio.run(scan_target(target, timeout_seconds=0.2))
    assert time.monotonic() - started < 5


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_remote_fixture(port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, str(REMOTE_FIXTURE), "--port", str(port)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise AssertionError(f"remote MCP fixture did not listen on port {port}")


def _stop_process(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
