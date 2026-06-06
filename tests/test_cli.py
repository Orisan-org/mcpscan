import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from typer.testing import CliRunner

from mcpscan.cli import app

runner = CliRunner()


def test_list_checks_works() -> None:
    result = runner.invoke(app, ["list-checks"])

    assert result.exit_code == 0
    assert "MCP-001" in result.output
    assert "MCP-002" in result.output
    assert "deferred" in result.output


def test_help_only_shows_working_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.output
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
    assert "Local config/path scanning is not supported yet" in result.output


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
