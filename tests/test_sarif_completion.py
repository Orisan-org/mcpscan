"""Slice 8 — SARIF a real consumer can read.

STRUCTURAL CONFORMANCE, not full schema validation. There is no offline SARIF
2.1.0 schema in this project's dependency set, and fetching one at test time
would make the suite depend on the network. What is asserted here is the set of
spec requirements that actually bite: member names SARIF defines, required
fields, and taxonomy references resolving.

The bug that motivated it: the run carried a singular `invocation` object.
SARIF 2.1.0 has no such member — it is `invocations`, an array — so every
checks-not-run notification was written to a key no conformant consumer would
ever look at. They existed and were invisible, which is worse than absent
because the tests said they were there.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan.capabilities import OWASP_MCP_REFERENCES, owasp_coverage
from mcpscan.checks.registry import check_catalogue
from mcpscan.cli import app

runner = CliRunner()
PYEXE = sys.executable
MALICIOUS = f"{PYEXE} tests/fixtures/malicious_server.py"


@pytest.fixture()
def config(tmp_path: Path) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "npx", "args": ["-y", "srv", "/Users/alice"]},
                    "b": {"url": "http://x.invalid/mcp"},
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _scan_sarif(*args: str) -> dict:
    out = runner.invoke(app, [*args, "--output", "sarif"])
    return json.loads(out.stdout)


def _both(config: Path) -> list[tuple[str, dict]]:
    return [
        ("scan", _scan_sarif("scan", "--command", MALICIOUS, "--no-execute")),
        ("scan-config", _scan_sarif("scan-config", str(config), "--no-execute")),
    ]


# ------------------------------------------------------- structural conformance


def test_the_run_uses_the_member_names_sarif_defines(config: Path) -> None:
    for name, payload in _both(config):
        run = payload["runs"][0]
        assert "invocation" not in run, f"{name}: SARIF has no singular `invocation` member"
        assert isinstance(run["invocations"], list), name
        assert run["invocations"], name
        assert run["invocations"][0]["executionSuccessful"] is True, name


def test_top_level_shape(config: Path) -> None:
    for name, payload in _both(config):
        assert payload["version"] == "2.1.0", name
        assert payload["$schema"].endswith("sarif-2.1.0.json"), name
        assert isinstance(payload["runs"], list), name
        driver = payload["runs"][0]["tool"]["driver"]
        assert driver["name"] and driver["version"], name


def test_every_result_references_a_declared_rule(config: Path) -> None:
    for name, payload in _both(config):
        run = payload["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in declared, f"{name}: {result['ruleId']} is not declared"
            assert result["level"] in {"error", "warning", "note", "none"}, name


# ------------------------------------------------------- tier on every result


def test_every_result_states_its_evidence_tier(config: Path) -> None:
    """Per result, not only per run: scan-config produces one run over several
    servers and they need not share a tier."""
    for name, payload in _both(config):
        for result in payload["runs"][0]["results"]:
            assert result["properties"]["evidence_tier"] in {"config", "surface", "live"}, name


def test_a_replay_and_a_live_scan_report_different_tiers(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    runner.invoke(
        app,
        [
            "snapshot",
            "--command",
            MALICIOUS,
            "--out",
            str(snapshot),
            "--profile",
            "full",
            "--label",
            "t",
        ],
    )
    live = _scan_sarif("scan", "--command", MALICIOUS)
    replayed = _scan_sarif("scan", "--tier", "surface", "--from-snapshot", str(snapshot))
    assert {r["properties"]["evidence_tier"] for r in live["runs"][0]["results"]} == {"live"}
    assert {r["properties"]["evidence_tier"] for r in replayed["runs"][0]["results"]} == {"surface"}


# ------------------------------------------------------- OWASP as a taxonomy


def test_the_owasp_taxonomy_is_declared_with_all_ten_categories(config: Path) -> None:
    for name, payload in _both(config):
        taxonomy = payload["runs"][0]["taxonomies"][0]
        assert taxonomy["name"] == "OWASP MCP Top 10", name
        assert {taxon["id"] for taxon in taxonomy["taxa"]} == set(OWASP_MCP_REFERENCES), name
        # isComprehensive false: three categories have no check behind them.
        assert taxonomy["isComprehensive"] is False, name


def test_the_taxonomy_reports_coverage_from_the_registry(config: Path) -> None:
    taxonomy = _both(config)[0][1]["runs"][0]["taxonomies"][0]
    coverage = owasp_coverage()
    for taxon in taxonomy["taxa"]:
        assert taxon["properties"]["coverage"] == coverage[taxon["id"]]["status"]
    uncovered = {
        t["id"] for t in taxonomy["taxa"] if t["properties"]["coverage"] == "no_check_implemented"
    }
    assert uncovered == {"MCP06", "MCP08"}


def test_every_result_points_into_the_taxonomy(config: Path) -> None:
    for name, payload in _both(config):
        run = payload["runs"][0]
        taxa_ids = {taxon["id"] for taxon in run["taxonomies"][0]["taxa"]}
        guid = run["taxonomies"][0]["guid"]
        for result in run["results"]:
            reference = result["taxa"][0]
            assert reference["id"] in taxa_ids, name
            assert reference["guid"] == guid, name
            assert result["properties"]["owasp_mcp"] == reference["id"], name


def test_every_rule_relates_to_its_category(config: Path) -> None:
    payload = _both(config)[0][1]
    run = payload["runs"][0]
    by_id = {entry.id: entry.owasp_mcp for entry in check_catalogue()}
    for rule in run["tool"]["driver"]["rules"]:
        target = rule["relationships"][0]["target"]
        assert target["id"] == by_id[rule["id"]]
        assert target["guid"] == run["taxonomies"][0]["guid"]


# ------------------------------------------------------- not-run consistency


def test_checks_not_run_appear_for_both_commands(config: Path) -> None:
    for name, payload in _both(config):
        notifications = payload["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert notifications, f"{name}: a config-tier run must report what it did not check"
        for note in notifications:
            assert note["descriptor"]["id"].startswith("MCP-"), name
            assert note["properties"]["outcome"] == "not_run", name
            assert note["properties"]["evidence_tier"] == "config", name
            assert note["message"]["text"], name


def test_a_live_scan_reports_no_not_run_notifications() -> None:
    payload = _scan_sarif("scan", "--command", MALICIOUS)
    assert payload["runs"][0]["invocations"][0]["toolExecutionNotifications"] == []


def test_clean_is_distinguishable_from_not_looked_at(config: Path) -> None:
    """The property the tier system exists for, at the format boundary."""
    payload = _scan_sarif("scan", "--command", MALICIOUS, "--no-execute")
    run = payload["runs"][0]
    not_run = {n["descriptor"]["id"] for n in run["invocations"][0]["toolExecutionNotifications"]}
    fired = {r["ruleId"] for r in run["results"]}
    declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    silent_and_ran = declared - not_run - fired
    assert not_run, "some checks did not run and SARIF must say so"
    assert not (not_run & fired), "a check cannot both not run and produce a result"
    assert "MCP-001" in not_run and "MCP-001" not in silent_and_ran


# ------------------------------------------------------- the invariants hold


def _keys(node: object) -> set[str]:
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, list):
        return {k for item in node for k in _keys(item)}
    return set()


def test_no_snippet_key_is_ever_populated(config: Path) -> None:
    """SARIF allows server-supplied text in region.snippet; payload_stored=false forbids it.

    Asserted on the KEY, not on the substring. A substring search over the
    whole document also matched this test's own name, which pytest embeds in
    the tmp path and the reporter records as the artifact URI — a false
    positive that says nothing about the reporter.
    """
    for name, payload in _both(config):
        assert "snippet" not in _keys(payload), name


def test_sarif_is_byte_identical_across_runs(config: Path) -> None:
    first = runner.invoke(
        app, ["scan-config", str(config), "--no-execute", "--output", "sarif"]
    ).stdout
    second = runner.invoke(
        app, ["scan-config", str(config), "--no-execute", "--output", "sarif"]
    ).stdout
    assert first == second
