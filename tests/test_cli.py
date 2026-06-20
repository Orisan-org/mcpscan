import json
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from typer.testing import CliRunner

from mcpscan.cli import _push_envelope, app
from mcpscan.errors import McpScanError

runner = CliRunner()


def test_list_checks_works() -> None:
    result = runner.invoke(app, ["list-checks"])

    assert result.exit_code == 0
    assert "MCP-001" in result.output
    assert "MCP-002" in result.output
    assert "CAPABILITY" in result.output
    assert "OWASP" in result.output
    assert "prompt_anomaly" in result.output
    assert "MCP03" in result.output
    assert "surface_drift" in result.output
    assert "active" in result.output


def test_help_only_shows_working_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.output
    assert "scan-config" in result.output
    assert "list-checks" in result.output
    assert "version" in result.output
    assert "baseline" not in result.output
    assert "diff" not in result.output


def test_scan_invalid_target_returns_usage_error() -> None:
    result = runner.invoke(app, ["scan", "server.py"])

    assert result.exit_code == 2
    assert "Input error" in result.output


def test_scan_local_config_path_explains_unsupported_state(tmp_path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text("{}", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(config)])

    assert result.exit_code == 2
    assert "scan-config" in result.output


def test_scan_rejects_header_with_stdio_command() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--command",
            "python server.py",
            "--header",
            "Authorization: Bearer fake",
        ],
    )

    assert result.exit_code == 2
    assert "--header is only supported for remote HTTP/SSE transports" in result.output


def test_version_works() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_module_entrypoint_help_works() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "mcpscan", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "baseline" not in result.stdout
    assert "diff" not in result.stdout


def test_console_script_help_works() -> None:
    script_name = "mcpscan.exe" if sys.platform == "win32" else "mcpscan"
    executable = Path(sysconfig.get_path("scripts")) / script_name
    if not executable.exists():
        executable_from_path = shutil.which("mcpscan")
        assert executable_from_path is not None
        executable = Path(executable_from_path)

    result = subprocess.run(
        [str(executable), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "baseline" not in result.stdout
    assert "diff" not in result.stdout


def write_config(tmp_path, payload: dict) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_scan_config_help_works() -> None:
    result = runner.invoke(app, ["scan-config", "--help"])

    assert result.exit_code == 0
    assert "scan-config" in result.output
    assert "CONFIG_PATH" in result.output
    assert "Execute configured" in result.output


def test_scan_config_yes_json_report(tmp_path) -> None:
    config = write_config(
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
                    "env": {"SECRET": "hunter2"},
                },
            }
        },
    )
    out = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["scan-config", str(config), "--yes", "--output", "json", "--out", str(out)],
    )

    assert result.exit_code == 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["config"]["servers_total"] == 2
    assert payload["config"]["servers_scanned"] == 2
    findings = [finding for server in payload["server_results"] for finding in server["findings"]]
    assert findings
    assert all(finding["payload_stored"] is False for finding in findings)
    assert "hunter2" not in out.read_text(encoding="utf-8")


def test_scan_config_can_write_shared_envelope(tmp_path) -> None:
    config = write_config(
        tmp_path,
        {
            "mcpServers": {
                "malicious": {
                    "command": sys.executable,
                    "args": ["tests/fixtures/malicious_server.py"],
                },
            }
        },
    )
    out = tmp_path / "report.json"
    envelope_out = tmp_path / "envelope.json"

    result = runner.invoke(
        app,
        [
            "scan-config",
            str(config),
            "--yes",
            "--output",
            "json",
            "--out",
            str(out),
            "--envelope-out",
            str(envelope_out),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(envelope_out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0.0"
    assert payload["producer"]["tool"] == "mcpscan"
    assert payload["inventory"]
    assert payload["coverage"]
    assert payload["findings"]


def test_scan_config_can_push_shared_envelope(tmp_path, monkeypatch) -> None:
    config = write_config(
        tmp_path,
        {
            "mcpServers": {
                "malicious": {
                    "command": sys.executable,
                    "args": ["tests/fixtures/malicious_server.py"],
                },
            }
        },
    )
    calls = []

    class FakeResponse:
        status_code = 202
        text = '{"run":{"run_id":"run_123"}}'

        def json(self):
            return {"run": {"run_id": "run_123"}}

    def fake_post(url, *, content, headers, timeout):
        calls.append(
            {
                "url": url,
                "content": content,
                "headers": headers,
                "timeout": timeout,
            }
        )
        return FakeResponse()

    monkeypatch.setattr("mcpscan.cli.httpx.post", fake_post)

    result = runner.invoke(
        app,
        [
            "scan-config",
            str(config),
            "--yes",
            "--output",
            "json",
            "--push-envelope",
            "--control-plane-url",
            "http://control-plane.test",
            "--ingest-token",
            "secret",
        ],
    )

    assert result.exit_code == 1
    assert "Envelope pushed: http://control-plane.test/v1/envelopes run_id=run_123" in result.output
    assert len(calls) == 1
    assert calls[0]["url"] == "http://control-plane.test/v1/envelopes"
    assert calls[0]["headers"] == {
        "content-type": "application/json",
        "authorization": "Bearer secret",
    }
    assert calls[0]["timeout"] == 10.0
    payload = json.loads(calls[0]["content"])
    assert payload["schema_version"] == "1.0.0"
    assert payload["producer"]["tool"] == "mcpscan"
    assert payload["findings"]


def test_push_envelope_raises_when_control_plane_rejects(monkeypatch) -> None:
    class FakeResponse:
        status_code = 400
        text = '{"error":"invalid_envelope"}'

    def fake_post(url, *, content, headers, timeout):
        return FakeResponse()

    monkeypatch.setattr("mcpscan.cli.httpx.post", fake_post)

    try:
        _push_envelope("{}", "http://control-plane.test/", None)
    except McpScanError as exc:
        assert "Control plane rejected envelope: HTTP 400" in str(exc)
        assert "invalid_envelope" in str(exc)
    else:
        raise AssertionError("expected McpScanError")


def test_scan_config_without_yes_can_decline_execution(tmp_path) -> None:
    sentinel = tmp_path / "executed.txt"
    config = write_config(
        tmp_path,
        {
            "mcpServers": {
                "would-execute": {
                    "command": sys.executable,
                    "args": [
                        "-c",
                        f"from pathlib import Path; Path({str(sentinel)!r}).write_text('x')",
                    ],
                }
            }
        },
    )

    result = runner.invoke(app, ["scan-config", str(config)], input="n\n")

    assert result.exit_code == 0
    assert "Execute and scan?" in result.output
    assert "no consent" in result.output
    assert not sentinel.exists()


def test_scan_config_all_failures_exit_enumeration(tmp_path) -> None:
    config = write_config(
        tmp_path,
        {"mcpServers": {"bad": {"command": sys.executable, "args": ["-c", "raise SystemExit(1)"]}}},
    )

    result = runner.invoke(app, ["scan-config", str(config), "--yes"])

    assert result.exit_code == 3
    assert "Failures:" in result.output
