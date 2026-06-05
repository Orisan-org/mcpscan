from typer.testing import CliRunner

from mcpscan.cli import app

runner = CliRunner()


def test_list_checks_works() -> None:
    result = runner.invoke(app, ["list-checks"])

    assert result.exit_code == 0
    assert "MCP-001" in result.output
    assert "MCP-002" in result.output
    assert "deferred" in result.output


def test_scan_invalid_target_returns_usage_error() -> None:
    result = runner.invoke(app, ["scan", "server.py"])

    assert result.exit_code == 2
    assert "Input error" in result.output


def test_version_works() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.output
