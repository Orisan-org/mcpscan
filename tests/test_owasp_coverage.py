"""OWASP MCP Top 10 coverage must describe what the registry actually does.

``OWASP_MCP_REFERENCES`` carries all ten categories as reference text. That is
useful for rendering a name next to a finding, and it is exactly the kind of
table that reads as a coverage claim when it is not one. Three of the ten have
no check behind them.

These tests make the gap load-bearing rather than documentary: the declared
uncovered set must equal the derived one in BOTH directions, so a category
cannot quietly move in either. Adding a check for MCP04 fails the build until
the declaration and the README are updated; deleting a check fails it too.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpscan.capabilities import (
    OWASP_MCP_REFERENCES,
    UNCOVERED_OWASP_MCP,
    UNCOVERED_REASONS,
    covered_owasp_mcp,
    owasp_coverage,
)
from mcpscan.checks.registry import check_catalogue

README = Path(__file__).resolve().parents[1] / "README.md"


def test_declared_uncovered_matches_the_registry() -> None:
    derived = frozenset(OWASP_MCP_REFERENCES) - covered_owasp_mcp()
    assert derived == UNCOVERED_OWASP_MCP, (
        "UNCOVERED_OWASP_MCP has drifted from the checks that actually exist.\n"
        f"  registry says uncovered: {sorted(derived)}\n"
        f"  capabilities.py declares: {sorted(UNCOVERED_OWASP_MCP)}\n"
        "Update the declaration, UNCOVERED_REASONS, and the README coverage line together."
    )


def test_every_category_with_reference_text_is_classified() -> None:
    coverage = owasp_coverage()
    assert set(coverage) == set(OWASP_MCP_REFERENCES)
    for category, entry in coverage.items():
        assert entry["status"] in {"checked", "no_check_implemented"}, category


def test_uncovered_categories_say_why() -> None:
    for category in UNCOVERED_OWASP_MCP:
        assert category in UNCOVERED_REASONS, f"{category} is uncovered with no stated reason"
        assert UNCOVERED_REASONS[category].startswith("no check"), category
    assert set(UNCOVERED_REASONS) == set(UNCOVERED_OWASP_MCP), (
        "a reason exists for a category that is not declared uncovered, or vice versa"
    )


def test_covered_categories_carry_no_uncovered_reason() -> None:
    # A leftover reason for a now-covered category would print "no check
    # implemented" next to a finding that check produced.
    for category in covered_owasp_mcp():
        assert category not in UNCOVERED_REASONS, category


def test_no_check_claims_an_unknown_category() -> None:
    for entry in check_catalogue():
        assert entry.owasp_mcp in OWASP_MCP_REFERENCES, (
            f"{entry.id} maps to {entry.owasp_mcp}, which has no reference text"
        )


def test_readme_coverage_line_matches_the_code() -> None:
    """The README states the covered and uncovered sets in prose. Pin it.

    The prose was already correct when this test was written. The point is that
    it stays correct when a check is added, which is precisely when someone
    updates the code and forgets the docs.
    """
    text = README.read_text(encoding="utf-8")
    line = next(
        (ln for ln in text.splitlines() if "Coverage maps to OWASP MCP classes" in ln),
        None,
    )
    assert line is not None, "README no longer states OWASP coverage; it must"

    claimed_covered = set(re.findall(r"MCP\d{2}", line.split(".")[0]))
    assert claimed_covered == set(covered_owasp_mcp()), (
        "README's covered list disagrees with the registry.\n"
        f"  README: {sorted(claimed_covered)}\n"
        f"  code:   {sorted(covered_owasp_mcp())}"
    )
    for category in UNCOVERED_OWASP_MCP:
        assert category in line, f"README does not name {category} as out of scope"
