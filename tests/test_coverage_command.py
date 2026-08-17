"""Slice 9 — the honest answer to "do you cover the OWASP MCP Top 10".

The answer is partially no and always will be. What matters is that the report
is derived from the registry rather than written by hand, so it cannot claim a
category nothing checks — and that it says what each check actually inspects,
because "MCP04: covered" is true and nearly useless on its own.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from mcpscan.capabilities import OWASP_MCP_REFERENCES, UNCOVERED_OWASP_MCP, covered_owasp_mcp
from mcpscan.checks.registry import active_checks, check_catalogue
from mcpscan.cli import app
from mcpscan.coverage import INSPECTS, coverage_rows, coverage_summary, render_coverage

runner = CliRunner()


def test_every_category_appears_exactly_once() -> None:
    rows = coverage_rows()
    assert [row["category"] for row in rows] == sorted(OWASP_MCP_REFERENCES)


def test_status_is_derived_from_the_registry_not_declared() -> None:
    for row in coverage_rows():
        has_checks = bool(row["checks"])
        assert row["status"] == ("checked" if has_checks else "no_check_implemented")
        assert (row["category"] in covered_owasp_mcp()) is has_checks


def test_uncovered_categories_match_the_declaration_and_say_why() -> None:
    uncovered = {row["category"] for row in coverage_rows() if row["status"] != "checked"}
    assert uncovered == set(UNCOVERED_OWASP_MCP)
    for row in coverage_rows():
        if row["status"] != "checked":
            assert row["detail"].startswith("no check")


def test_every_active_check_says_what_it_inspects() -> None:
    """A new check must not arrive and be summarised as merely 'covered'."""
    missing = [check.id for check in active_checks() if not INSPECTS.get(check.id)]
    assert not missing, f"no `inspects` text for: {missing}"
    catalogue_missing = [e.id for e in check_catalogue() if not INSPECTS.get(e.id)]
    assert not catalogue_missing, f"no `inspects` text for catalogue entries: {catalogue_missing}"


def test_inspects_has_no_entry_for_a_check_that_does_not_exist() -> None:
    known = {entry.id for entry in check_catalogue()}
    assert set(INSPECTS) <= known, f"stale entries: {set(INSPECTS) - known}"


def test_each_check_states_which_tiers_it_runs_at() -> None:
    for row in coverage_rows():
        for check in row["checks"]:
            assert check["tiers"], check["id"]


def test_the_narrowest_claims_are_spelled_out() -> None:
    """MCP04 is 'covered' by specifier pinning alone. Saying only 'covered'
    would let a reader assume dependency scanning that does not exist."""
    rows = {row["category"]: row for row in coverage_rows()}
    mcp04 = rows["MCP04"]["checks"][0]
    assert "NOT the dependency tree" in mcp04["inspects"]
    assert "curated seed list" in rows["MCP09"]["checks"][0]["inspects"]


def test_the_text_report_refuses_to_read_as_a_coverage_claim() -> None:
    text = render_coverage()
    assert "8 of 10 categories have a check" in text
    assert "This is not a claim of coverage" in text
    assert "nothing in mcpscan looks at them today" in text
    for category in UNCOVERED_OWASP_MCP:
        assert f"{category}  " in text
    assert "NO CHECK" in text


def test_the_command_prints_text_and_json() -> None:
    text = runner.invoke(app, ["coverage"])
    assert text.exit_code == 0
    assert "OWASP MCP Top 10" in text.stdout

    payload = json.loads(runner.invoke(app, ["coverage", "--output", "json"]).stdout)
    assert payload["total"] == 10
    assert payload["checked"] == len(covered_owasp_mcp())
    assert set(payload["uncovered"]) == set(UNCOVERED_OWASP_MCP)


def test_an_unknown_output_is_refused() -> None:
    assert runner.invoke(app, ["coverage", "--output", "yaml"]).exit_code == 2


def test_the_summary_counts_agree_with_the_rows() -> None:
    summary = coverage_summary()
    assert summary["checked"] == sum(1 for row in summary["rows"] if row["status"] == "checked")
    assert summary["total"] == len(summary["rows"])
    assert summary["checked"] + len(summary["uncovered"]) == summary["total"]


def test_output_is_deterministic() -> None:
    assert render_coverage() == render_coverage()
    assert runner.invoke(app, ["coverage"]).stdout == runner.invoke(app, ["coverage"]).stdout
