"""Evidence tiers: what a scan was actually able to look at.

A scan that never started the server cannot read a tool description, because
tool descriptions do not exist in an MCP config file — they live inside the
server and are only knowable by asking it. Six of the nine checks read
``ctx.tools``. Run them with no server and they find nothing, which is
indistinguishable from finding nothing wrong.

That is the false-assurance failure this project exists to avoid, so the tier is
recorded on every report and every check declares what it needs:

    config   an MCP config file. No execution, no network. Command, arguments,
             environment variable NAMES, transport, URL, headers.
    surface  a previously captured surface snapshot. No execution, no network,
             but tool descriptions and schemas are present.
    live     a running server. Everything, at the cost of executing it.

A check that could not run is reported as not run, with the reason. It is never
reported as passing, and it never silently disappears from the output — that is
the existing no-suppression invariant applied to coverage rather than findings.
"""

from __future__ import annotations

from enum import Enum


class EvidenceTier(str, Enum):
    CONFIG = "config"
    SURFACE = "surface"
    LIVE = "live"


#: What each tier can see, for operator-facing copy.
TIER_DESCRIPTIONS: dict[EvidenceTier, str] = {
    EvidenceTier.CONFIG: (
        "config only: the server was not started and not contacted. "
        "Tool descriptions and schemas were not available."
    ),
    EvidenceTier.SURFACE: (
        "captured surface: tool descriptions and schemas from a stored snapshot. "
        "The server was not started, so the snapshot may be out of date."
    ),
    EvidenceTier.LIVE: "live server: the server was started or contacted and its current surface read.",
}

#: Tiers that provide a tool surface. Ordering is deliberately NOT a hierarchy —
#: `config` is not "less live", it is a different kind of evidence, and a
#: config-tier check (an unpinned package specifier) has no live equivalent.
SURFACE_TIERS: frozenset[EvidenceTier] = frozenset({EvidenceTier.SURFACE, EvidenceTier.LIVE})

#: Every tier. A check requiring this runs everywhere.
ALL_TIERS: frozenset[EvidenceTier] = frozenset(EvidenceTier)


class CheckNotRun:
    """A check the tier could not supply inputs for.

    Carried in the report beside the findings. Not a finding — nothing was
    detected — but not silence either.
    """

    __slots__ = ("check_id", "title", "owasp_mcp", "reason")

    def __init__(self, *, check_id: str, title: str, owasp_mcp: str, reason: str) -> None:
        self.check_id = check_id
        self.title = title
        self.owasp_mcp = owasp_mcp
        self.reason = reason

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "owasp_mcp": self.owasp_mcp,
            "reason": self.reason,
        }

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CheckNotRun) and self.to_dict() == other.to_dict()

    def __repr__(self) -> str:
        return f"CheckNotRun({self.check_id}: {self.reason})"


def reason_for(check_id: str, required: frozenset[EvidenceTier], tier: EvidenceTier) -> str:
    """Say what was missing, in terms of evidence rather than internals."""
    if required >= SURFACE_TIERS or required == SURFACE_TIERS:
        return (
            f"needs the server's tool surface; tier {tier.value} did not provide one "
            "(capture one with `mcpscan snapshot`, or allow execution)"
        )
    wanted = ", ".join(sorted(t.value for t in required))
    return f"needs evidence tier {wanted}; this scan ran at tier {tier.value}"


def grade_is_assessable(checks_not_run: list[dict[str, str]]) -> bool:
    """A grade means something only when every check actually ran."""
    return not checks_not_run


def grade_label(grade: str, tier: EvidenceTier, checks_not_run: list[dict[str, str]]) -> str:
    """The grade, or an explicit refusal to give one.

    A config-tier scan of a hostile server finds nothing, because the six checks
    that would find something never ran. Scoring that as `A` is not a rounding
    error, it is the false-assurance failure this project exists to avoid — and
    the repo already has the instinct: `_worst_grade_label` refuses a letter
    when no server was scanned. This is the same rule one step further in.

    So the letter is WITHHELD rather than annotated. An annotated `A` still
    reads as an A to someone skimming.
    """
    if grade_is_assessable(checks_not_run):
        return grade
    return f"not assessed ({tier.value} tier, {len(checks_not_run)} check(s) did not run)"
