"""Slice D of BRIEF-0.1.1.md, bug 3: the mcp SDK version guard.

The pin in pyproject.toml is the fix. These cover the backstop that fires when the pin
is bypassed, and the property that made bug 3 invisible for a release: an unsupported
SDK must produce a refusal that names the version, not a scan that silently omits a
transport.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from mcpscan import sdk_compat
from mcpscan.cli import app
from mcpscan.constants import EXIT_INTERNAL
from mcpscan.sdk_compat import (
    MCP_SDK_MAX_EXCLUSIVE,
    MCP_SDK_MIN,
    SdkCompatibilityError,
    mcp_sdk_problem,
    verify_mcp_sdk,
)

runner = CliRunner()


def _pin_version(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    monkeypatch.setattr(sdk_compat, "installed_mcp_version", lambda: value)


def test_pin_bounds_match_the_declared_requirement() -> None:
    """The constants and the human-readable requirement string must not drift apart."""
    assert sdk_compat.MCP_SDK_REQUIREMENT == ">=1.0.0,<2"
    assert MCP_SDK_MIN == (1, 0, 0)
    assert MCP_SDK_MAX_EXCLUSIVE == (2, 0, 0)


def test_pyproject_pin_matches_the_guard() -> None:
    """A widened pin without a widened guard would let bug 3 back in silently."""
    import pathlib
    import tomllib

    root = pathlib.Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    mcp_requirements = [
        dep for dep in pyproject["project"]["dependencies"] if dep.startswith("mcp[")
    ]
    assert mcp_requirements == [f"mcp[cli]{sdk_compat.MCP_SDK_REQUIREMENT}"], (
        f"pyproject declares {mcp_requirements}, guard declares "
        f"mcp[cli]{sdk_compat.MCP_SDK_REQUIREMENT}"
    )


@pytest.mark.parametrize("supported", ["1.0.0", "1.9.4", "1.29.0", "1.29.0rc1"])
def test_supported_versions_report_no_problem(
    monkeypatch: pytest.MonkeyPatch, supported: str
) -> None:
    _pin_version(monkeypatch, supported)

    assert mcp_sdk_problem() is None
    verify_mcp_sdk()


@pytest.mark.parametrize("unsupported", ["2.0.0", "2.0.0rc1", "2.1.3", "3.0.0"])
def test_mcp_2_and_later_are_refused_by_version(
    monkeypatch: pytest.MonkeyPatch, unsupported: str
) -> None:
    _pin_version(monkeypatch, unsupported)

    problem = mcp_sdk_problem()
    assert problem is not None
    assert unsupported in problem, "the refusal must name the installed version"
    assert ">=1.0.0,<2" in problem, "the refusal must name the supported range"

    with pytest.raises(SdkCompatibilityError):
        verify_mcp_sdk()


def test_versions_below_the_floor_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_version(monkeypatch, "0.9.0")

    problem = mcp_sdk_problem()
    assert problem is not None
    assert "0.9.0" in problem


def test_missing_sdk_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_version(monkeypatch, None)

    problem = mcp_sdk_problem()
    assert problem is not None
    assert "not installed" in problem


def test_unparseable_version_is_refused_not_waved_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown must not read as fine. Silence on an unknown version is how bug 3 hid."""
    _pin_version(monkeypatch, "not-a-version")

    problem = mcp_sdk_problem()
    assert problem is not None
    assert "not-a-version" in problem


def test_scan_refuses_to_run_on_an_unsupported_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point: refuse before scanning, rather than emitting a partial verdict."""
    _pin_version(monkeypatch, "2.0.0")

    result = runner.invoke(app, ["scan", "--command", "python does-not-matter.py"])

    assert result.exit_code == EXIT_INTERNAL
    assert "Incompatible mcp SDK" in result.output
    assert "2.0.0" in result.output
    assert "Grade" not in result.output, "a refused run must not report a grade"


def test_scan_config_refuses_to_run_on_an_unsupported_sdk(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    _pin_version(monkeypatch, "2.0.0")
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {}}', encoding="utf-8")

    result = runner.invoke(app, ["scan-config", str(config), "--yes"])

    assert result.exit_code == EXIT_INTERNAL
    assert "Incompatible mcp SDK" in result.output


@pytest.mark.parametrize("command", [["version"], ["list-checks"]])
def test_diagnostic_commands_still_work_on_an_unsupported_sdk(
    monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    """A user on a broken install must still be able to report what they have."""
    _pin_version(monkeypatch, "2.0.0")

    result = runner.invoke(app, command)

    assert result.exit_code == 0
