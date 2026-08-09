"""Slice A of BRIEF-0.1.1.md: the wheel test harness.

Every other test in this suite imports ``mcpscan`` from ``src/`` (see
``tests/conftest.py``) and runs against whatever SDK the developer's environment
happens to have resolved. That is why bug 3 shipped: the repo tree passed while the
artifact users actually install was broken. CI structurally could not see it.

This module tests the **artifact**, not the tree:

1. build the wheel with ``uv build``,
2. install it into a clean virtualenv with **no version constraints**, so the
   dependency solver resolves exactly what a user on PyPI gets today,
3. run the README's headline commands from that venv's console script against real
   fixture MCP servers.

Two environments, deliberately separate
---------------------------------------
``wheel_env``   the artifact under test. Unconstrained on purpose. Constraining it
                would defeat the entire point of this harness.
``fixture_env`` the MCP servers being scanned. Pinned to ``mcp[cli]<2`` because
                ``tests/fixtures/*.py`` use ``mcp.server.fastmcp.FastMCP``, which mcp
                2.0.0 removed. The server's SDK version is not part of mcpscan's
                artifact, so pinning it here is legitimate and keeps a fixture-side
                breakage from masquerading as an mcpscan defect.

Subprocesses run with ``cwd`` outside the repo and ``PYTHONPATH`` cleared so the repo's
``src/`` can never leak into the environment under test.

Scope
-----
Slice A only. These tests are deliberately **not** here:

* bug 1, the inferred-purpose/adjudicator equivalence test  -> Slice B
* bug 2 ``scan-config`` environment inheritance, and bug 2b
  "no grade when nothing was scanned"                       -> Slice C
* the fix for bug 3 (``mcp[cli]>=1.0.0,<2``, fail loudly instead of degrading) and
  bug 4's repository URL                                    -> Slice D

Adding them now would leave main failing for four reasons at once and destroy the
signal this slice exists to produce.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.wheel

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

# The fixture servers use mcp.server.fastmcp.FastMCP, removed in mcp 2.0.0.
FIXTURE_SDK_SPEC = "mcp[cli]>=1.0.0,<2"

SUBPROCESS_TIMEOUT = 180


# --------------------------------------------------------------------------- helpers


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel; see CI wheel-harness job")
    return uv


def _clean_env(venv: Path) -> dict[str, str]:
    """Environment for a subprocess run against ``venv``, with the repo tree kept out."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    env["PATH"] = f"{_bin_dir(venv)}{os.pathsep}{env.get('PATH', '')}"
    return env


def _bin_dir(venv: Path) -> Path:
    return venv / ("Scripts" if sys.platform == "win32" else "bin")


def _exe(venv: Path, name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    return _bin_dir(venv) / f"{name}{suffix}"


def _run(argv: list[str], *, venv: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=_clean_env(venv),
        timeout=SUBPROCESS_TIMEOUT,
    )


def _mcpscan(
    args: list[str], *, wheel_env: Path, workdir: Path
) -> subprocess.CompletedProcess[str]:
    """Invoke the installed console script — the entry point a real user gets."""
    return _run([str(_exe(wheel_env, "mcpscan")), *args], venv=wheel_env, cwd=workdir)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[str], timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"fixture MCP server exited early with code {process.returncode}\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise AssertionError(f"fixture MCP server did not listen on port {port} within {timeout}s")


def _stop(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)


def _fail(label: str, result: subprocess.CompletedProcess[str], *, venv: Path | None = None) -> str:
    message = (
        f"{label}\n"
        f"  exit code: {result.returncode}\n"
        f"  stdout:\n{result.stdout}\n"
        f"  stderr:\n{result.stderr}"
    )
    if venv is not None:
        message += f"  resolved dependencies:\n{_resolved_deps(venv)}"
    return message


def _resolved_deps(venv: Path) -> str:
    """What the solver actually picked. Makes a failure attributable to a version pin."""
    frozen = subprocess.run(
        [_uv(), "pip", "freeze", "--python", str(_exe(venv, "python"))],
        check=False,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    if frozen.returncode != 0:
        return "    <uv pip freeze failed>\n"
    return "".join(f"    {line}\n" for line in frozen.stdout.splitlines() if line.strip())


# -------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="session")
def wheel_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the distribution artifacts from the repo, exactly as a release would."""
    dist = tmp_path_factory.mktemp("dist")
    result = subprocess.run(
        [_uv(), "build", "--out-dir", str(dist), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    assert result.returncode == 0, _fail("uv build failed", result)

    wheels = sorted(dist.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel in {dist}, got {[w.name for w in wheels]}"
    return wheels[0]


@pytest.fixture(scope="session")
def wheel_env(tmp_path_factory: pytest.TempPathFactory, wheel_path: Path) -> Path:
    """A clean venv with the wheel installed and NO constraints on its dependencies.

    Unconstrained is the whole point: this resolves what a user installing from PyPI
    resolves today. Pinning anything here would reintroduce the blind spot that let
    bug 3 ship.
    """
    venv = tmp_path_factory.mktemp("wheel-env") / "venv"
    create = subprocess.run(
        [_uv(), "venv", str(venv)],
        check=False,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    assert create.returncode == 0, _fail("uv venv failed for the wheel environment", create)

    install = subprocess.run(
        [_uv(), "pip", "install", "--python", str(_exe(venv, "python")), str(wheel_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    assert install.returncode == 0, _fail(f"installing {wheel_path.name} failed", install)
    return venv


@pytest.fixture(scope="session")
def fixture_env(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A venv for running the fixture MCP servers. Pinned, and not under test."""
    venv = tmp_path_factory.mktemp("fixture-env") / "venv"
    create = subprocess.run(
        [_uv(), "venv", str(venv)],
        check=False,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    assert create.returncode == 0, _fail("uv venv failed for the fixture environment", create)

    install = subprocess.run(
        [_uv(), "pip", "install", "--python", str(_exe(venv, "python")), FIXTURE_SDK_SPEC],
        check=False,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    assert install.returncode == 0, _fail(f"installing {FIXTURE_SDK_SPEC} failed", install)
    return venv


@pytest.fixture(scope="session")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A directory outside the repo, so nothing resolves against the source tree."""
    return tmp_path_factory.mktemp("workdir")


# ----------------------------------------------------------------------------- tests


def test_wheel_is_the_orisan_mcpscan_distribution(wheel_path: Path) -> None:
    """The artifact users install is `orisan-mcpscan`; `mcpscan` is name-blocked on PyPI."""
    assert wheel_path.name.startswith("orisan_mcpscan-"), (
        f"built wheel is named {wheel_path.name!r}; the published distribution is orisan-mcpscan"
    )


def test_installed_console_script_reports_its_version(wheel_env: Path, workdir: Path) -> None:
    result = _mcpscan(["version"], wheel_env=wheel_env, workdir=workdir)

    assert result.returncode == 0, _fail("mcpscan version failed", result)
    assert "0.1.0" in result.stdout, _fail("mcpscan version did not report 0.1.0", result)


def test_installed_console_script_lists_checks(wheel_env: Path, workdir: Path) -> None:
    result = _mcpscan(["list-checks"], wheel_env=wheel_env, workdir=workdir)

    assert result.returncode == 0, _fail("mcpscan list-checks failed", result)
    assert "MCP-010" in result.stdout, _fail("list-checks did not name the checks", result)


def test_benign_stdio_scan_grades_a_from_the_wheel(
    wheel_env: Path, fixture_env: Path, workdir: Path
) -> None:
    """README: `mcpscan scan --command "... benign_server.py"` -> grade A, no findings."""
    report = workdir / "benign.json"
    result = _mcpscan(
        [
            "scan",
            "--command",
            f"{_exe(fixture_env, 'python')} {FIXTURES / 'benign_server.py'}",
            "--output",
            "json",
            "--out",
            str(report),
        ],
        wheel_env=wheel_env,
        workdir=workdir,
    )

    assert result.returncode == 0, _fail("benign stdio scan did not exit 0", result)
    payload = json.loads(report.read_text())
    assert payload["verdict_summary"]["grade"] == "A", (
        f"benign fixture graded {payload['verdict_summary']['grade']}, expected A"
    )
    assert payload["findings"] == []


def test_malicious_stdio_scan_finds_risks_and_stores_no_payloads(
    wheel_env: Path, fixture_env: Path, workdir: Path
) -> None:
    """README: the risky fixture must trip the threshold and exit 1, storing no evidence."""
    report = workdir / "malicious.json"
    result = _mcpscan(
        [
            "scan",
            "--command",
            f"{_exe(fixture_env, 'python')} {FIXTURES / 'malicious_server.py'}",
            "--severity-threshold",
            "high",
            "--output",
            "json",
            "--out",
            str(report),
        ],
        wheel_env=wheel_env,
        workdir=workdir,
    )

    assert result.returncode == 1, _fail("malicious stdio scan did not exit 1", result)
    payload = json.loads(report.read_text())
    assert payload["findings"], "malicious fixture produced no findings"
    assert all(finding["payload_stored"] is False for finding in payload["findings"])
    assert "not actually running" not in json.dumps(payload)


def test_streamable_http_scan_works_from_the_wheel(
    wheel_env: Path, fixture_env: Path, workdir: Path
) -> None:
    """Bug 3 (BRIEF-0.1.1.md): remote scanning is dead on every fresh install.

    The README calls Streamable HTTP "the primary tested remote transport in this
    release". This asserts that claim against the built wheel in a clean environment.

    On current main it fails: the wheel declares ``mcp[cli]>=1.0.0`` with no upper
    bound, PyPI resolves mcp 2.0.0, which renamed ``streamablehttp_client`` to
    ``streamable_http_client``, and ``connectors/remote.py`` swallows the ImportError
    and degrades to "Streamable HTTP transport is not available in the installed mcp
    SDK." rather than failing loudly.

    This asserts the scan *works* rather than asserting the current error text. A test
    that pinned the error message would pass on main today and go green the moment
    someone reworded the string, which is not a gate.
    """
    port = _free_port()
    server = subprocess.Popen(
        [
            str(_exe(fixture_env, "python")),
            str(FIXTURES / "remote_streamable_server.py"),
            "--port",
            str(port),
        ],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_clean_env(fixture_env),
    )
    report = workdir / "remote.json"
    try:
        _wait_for_port(port, server)
        result = _mcpscan(
            [
                "scan",
                f"http://127.0.0.1:{port}/mcp",
                "--transport",
                "http",
                "--output",
                "json",
                "--out",
                str(report),
            ],
            wheel_env=wheel_env,
            workdir=workdir,
        )
    finally:
        _stop(server)

    assert report.exists(), _fail(
        "the wheel could not scan a live Streamable HTTP MCP server (bug 3)",
        result,
        venv=wheel_env,
    )
    payload = json.loads(report.read_text())
    assert payload["server"]["name"] == "remote-risky-server", _fail(
        "the wheel did not enumerate the remote server (bug 3)", result, venv=wheel_env
    )
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert {"MCP-010", "MCP-030"}.issubset(finding_ids), (
        f"remote scan enumerated but found {sorted(finding_ids)}"
    )
    assert all(finding["payload_stored"] is False for finding in payload["findings"])
