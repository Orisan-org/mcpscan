"""Slice 4 — the ruleset digest.

A verdict is reproducible only if you know which rules produced it. The scanner
version pins the code; it does not pin the patterns, and a pattern change is
exactly what moves a verdict. This has to hold before anything is signed:
signing a verdict whose ruleset is unidentified signs an unreproducible claim.
"""

from __future__ import annotations

import importlib
import json
import re
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from mcpscan.checks.registry import PHASE1_CHECKS, active_checks
from mcpscan.cli import app
from mcpscan.ruleset import (
    RULESET_VERSION,
    canonical_manifest_json,
    check_signature,
    ruleset_digest,
    ruleset_manifest,
)

runner = CliRunner()
FIXTURE = f"{sys.executable} tests/fixtures/benign_server.py"


# ------------------------------------------------------------------ A4.1 sensitivity


def test_changing_a_pattern_changes_the_digest(monkeypatch) -> None:
    before = ruleset_digest()
    module = importlib.import_module("mcpscan.checks.prompt_injection")
    monkeypatch.setattr(module, "BASE64_RE", re.compile(r"\bDIFFERENT\b"))
    assert ruleset_digest() != before


def test_changing_a_private_pattern_changes_the_digest(monkeypatch) -> None:
    """The first filter skipped `_UPPER` names, leaving four checks' rules out."""
    before = ruleset_digest()
    module = importlib.import_module("mcpscan.checks.config_surface")
    monkeypatch.setattr(module, "_RUNNERS", {"npx", "somethingelse"})
    assert ruleset_digest() != before


def test_changing_a_keyword_list_changes_the_digest(monkeypatch) -> None:
    before = ruleset_digest()
    module = importlib.import_module("mcpscan.checks.command_injection")
    monkeypatch.setattr(module, "SQL_WORDS", ("database", "db"))
    assert ruleset_digest() != before


def test_changing_a_severity_changes_the_digest(monkeypatch) -> None:
    from mcpscan.models import Severity

    before = ruleset_digest()
    monkeypatch.setattr(type(active_checks()[0]), "severity", Severity.LOW)
    assert ruleset_digest() != before


# ------------------------------------------------------------------ A4.2 stability


def test_reordering_the_registry_does_not_change_the_digest(monkeypatch) -> None:
    """Execution order does not change what any check decides."""
    before = ruleset_digest()
    monkeypatch.setattr("mcpscan.checks.registry.PHASE1_CHECKS", list(reversed(PHASE1_CHECKS)))
    assert ruleset_digest() == before


def test_the_digest_is_stable_across_calls() -> None:
    assert ruleset_digest() == ruleset_digest()
    assert canonical_manifest_json() == canonical_manifest_json()


def test_the_manifest_is_json_serialisable_and_sorted() -> None:
    raw = canonical_manifest_json()
    parsed = json.loads(raw)
    ids = [check["id"] for check in parsed["checks"]]
    assert ids == sorted(ids)
    assert raw == json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def test_set_ordering_does_not_leak_into_the_digest() -> None:
    """Sets are unordered in Python; the canonical form must not be."""
    from mcpscan.ruleset import _canonical

    assert _canonical({"b", "a", "c"}) == _canonical({"c", "a", "b"})


def test_regex_flags_ignore_the_implicit_unicode_flag() -> None:
    from mcpscan.ruleset import _canonical

    # re.UNICODE is implicit for str patterns and its value has moved between
    # releases; including it would make the digest interpreter-dependent.
    assert _canonical(re.compile("x")) == {"regex": "x", "flags": 0}
    assert _canonical(re.compile("x", re.I))["flags"] != 0


# ------------------------------------------------------------------ A4.5 no pattern escapes


def test_every_compiled_pattern_in_a_check_module_is_in_the_manifest() -> None:
    """The guard that stops the constant filter from silently narrowing again."""
    manifest = ruleset_manifest()
    covered: dict[str, set[str]] = {}
    for entry in manifest["checks"]:
        covered.setdefault(entry["module"], set())
        for name, value in entry["rules"].items():
            covered[entry["module"]].add(name)
            if isinstance(value, dict) and "regex" in value:
                covered[entry["module"]].add(value["regex"])

    missing: list[str] = []
    for module_name in covered:
        module = importlib.import_module(module_name)
        for name, value in vars(module).items():
            if isinstance(value, re.Pattern) and name not in covered[module_name]:
                missing.append(f"{module_name}.{name}")
    assert not missing, f"compiled patterns outside the ruleset digest: {missing}"


def test_every_active_check_contributes_rule_data() -> None:
    for check in active_checks():
        signature = check_signature(check)
        assert signature["rules"], f"{check.id} contributes no rule data to the digest"


def test_no_rule_data_is_read_from_the_environment_or_network() -> None:
    """A ruleset that varies with the machine is not a ruleset."""
    modules = {type(check).__module__ for check in active_checks()}
    root = Path(__file__).resolve().parents[1] / "src"
    banned = ("os.environ", "getenv", "urlopen", "requests.", "httpx.", "socket.")
    for module_name in modules:
        source = (
            (root / Path(*module_name.split("."))).with_suffix(".py").read_text(encoding="utf-8")
        )
        for token in banned:
            assert token not in source, f"{module_name} reads rule data from {token}"


# ------------------------------------------------------------------ in the reports


def test_json_report_carries_version_and_digest() -> None:
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", "--output", "json"])
    scan = json.loads(out.stdout)["scan"]
    assert scan["ruleset_version"] == RULESET_VERSION
    assert scan["ruleset_digest"] == ruleset_digest()
    assert len(scan["ruleset_digest"]) == 64


def test_config_json_report_carries_version_and_digest(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"r": {"url": "https://x.invalid/mcp"}}}), encoding="utf-8"
    )
    out = runner.invoke(app, ["scan-config", str(config), "--no-execute", "--output", "json"])
    payload = json.loads(out.stdout)
    assert payload["ruleset_digest"] == ruleset_digest()


def test_sarif_carries_it_on_the_tool_driver() -> None:
    out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", "--output", "sarif"])
    driver = json.loads(out.stdout)["runs"][0]["tool"]["driver"]
    assert driver["properties"]["ruleset_digest"] == ruleset_digest()


def test_terminal_and_markdown_state_it() -> None:
    short = ruleset_digest()[:16]
    for args in (["--no-color"], ["--output", "md"]):
        out = runner.invoke(app, ["scan", "--command", FIXTURE, "--no-execute", *args])
        assert short in out.stdout


def test_the_ruleset_command_reports_and_can_dump_the_manifest() -> None:
    out = runner.invoke(app, ["ruleset"])
    assert ruleset_digest() in out.stdout
    dumped = runner.invoke(app, ["ruleset", "--manifest"])
    assert json.loads(dumped.stdout)["ruleset_version"] == RULESET_VERSION


# ------------------------------------------------------------------ A4.4 interpreter stability


def test_the_digest_is_identical_in_a_fresh_interpreter() -> None:
    """Catches anything derived from hash randomisation or import order."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from mcpscan.ruleset import ruleset_digest; print(ruleset_digest())",
        ],
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONHASHSEED": "random", "PATH": "/usr/bin:/bin"},
    )
    assert result.stdout.strip() == ruleset_digest()
