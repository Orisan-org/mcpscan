"""The honest answer to "do you cover the OWASP MCP Top 10".

The answer is no, and it always will be partially no, because a scanner that
never starts a server cannot assess what a server does at runtime and a
category like audit-and-logging is not visible from a tool list at all.

What this produces is the version of that answer someone can act on: which
categories have a check, which do not, and — for the ones that do — what the
check actually inspects, so a reader can judge whether "covered" means what
they need it to mean. `MCP04: covered` is true and close to useless on its own;
"covered by launch-specifier pinning only, dependency trees not inspected" is
the thing a security engineer is really asking for.

Everything here is derived from the check registry. The guard in
tests/test_owasp_coverage.py already prevents the declared and derived sets
from drifting apart, so this cannot claim a category no check emits.
"""

from __future__ import annotations

from typing import Any

from mcpscan.capabilities import OWASP_MCP_REFERENCES, UNCOVERED_REASONS
from mcpscan.checks.registry import check_catalogue
from mcpscan.tiers import ALL_TIERS

#: What each check inspects, in the reader's terms rather than the code's.
#:
#: Deliberately narrower than the check's title. A title says what a check is
#: called; this says what it looks at and, where it matters, what it does not.
#: There is a test asserting every active check has an entry, so a new check
#: cannot arrive and be silently summarised as "covered".
INSPECTS: dict[str, str] = {
    "MCP-001": "tool descriptions, for instructions aimed at the agent rather than the user",
    "MCP-002": "the recorded surface against a stored snapshot: tools, descriptions, schemas, launch command",
    "MCP-010": "tool descriptions and schemas, for capabilities beyond the server's declared purpose",
    "MCP-020": "tool, resource and prompt metadata, for credentials left in the text",
    "MCP-021": "tool descriptions, for access to credential stores, key material and dotfiles",
    "MCP-030": "tool input schemas, for parameters that reach a shell, an interpreter or a query",
    "MCP-040": "whether a remote server allowed enumeration without a caller-supplied credential",
    "MCP-041": "the transport scheme, for plaintext HTTP",
    "MCP-050": "server and tool names against a curated seed list of known MCP servers",
    "MCP-060": "environment values in the configuration, for credentials (values are never read into the report)",
    "MCP-061": "the launch command, for fetch-and-execute, shell composition, sudo, and TLS verification switched off",
    "MCP-062": "the launch specifier, for a floating version — NOT the dependency tree or package provenance",
    "MCP-063": "launch arguments, for filesystem roots, home directories and whole drives",
}


def coverage_rows() -> list[dict[str, Any]]:
    """One row per OWASP category, derived from the registry."""
    entries = sorted(check_catalogue(), key=lambda item: item.id)
    rows: list[dict[str, Any]] = []
    for category, title in sorted(OWASP_MCP_REFERENCES.items()):
        checks = [entry for entry in entries if entry.owasp_mcp == category]
        rows.append(
            {
                "category": category,
                "title": title,
                "status": "checked" if checks else "no_check_implemented",
                "detail": "" if checks else UNCOVERED_REASONS.get(category, "no check implemented"),
                "checks": [
                    {
                        "id": entry.id,
                        "title": entry.title,
                        "severity": entry.severity.value,
                        "status": entry.status,
                        "inspects": INSPECTS.get(entry.id, ""),
                        "tiers": _tier_label(entry.id),
                    }
                    for entry in checks
                ],
            }
        )
    return rows


def _tier_label(check_id: str) -> str:
    from mcpscan.checks.registry import active_checks

    for check in active_checks():
        if check.id == check_id:
            if check.requires == ALL_TIERS:
                return "every tier, including --no-execute"
            return ", ".join(sorted(tier.value for tier in check.requires))
    # Catalogue-only entries (drift) run wherever a baseline is supplied.
    return "with a baseline or snapshot"


def coverage_summary() -> dict[str, Any]:
    rows = coverage_rows()
    checked = [row for row in rows if row["status"] == "checked"]
    return {
        "total": len(rows),
        "checked": len(checked),
        "uncovered": [row["category"] for row in rows if row["status"] != "checked"],
        "rows": rows,
    }


def render_coverage(summary: dict[str, Any] | None = None) -> str:
    """A plain-text answer, for pasting into a reply to a security review."""
    data = summary or coverage_summary()
    lines = [
        f"OWASP MCP Top 10 — {data['checked']} of {data['total']} categories have a check.",
        "",
        "This is not a claim of coverage. A category with a check is a category",
        "something is looked at for; what is looked at is stated per check below.",
        "",
    ]
    for row in data["rows"]:
        mark = "checked" if row["status"] == "checked" else "NO CHECK"
        lines.append(f"{row['category']}  {row['title']}")
        lines.append(f"          {mark}")
        if row["status"] != "checked":
            lines.append(f"          {row['detail']}")
        for check in row["checks"]:
            lines.append(
                f"          {check['id']} ({check['severity']}) — inspects {check['inspects']}"
            )
            lines.append(f"          {' ' * len(check['id'])}   runs at: {check['tiers']}")
        lines.append("")
    if data["uncovered"]:
        lines.append(
            "Uncovered: " + ", ".join(data["uncovered"]) + ". These are not partially "
            "covered or planned; nothing in mcpscan looks at them today."
        )
    return "\n".join(lines) + "\n"
