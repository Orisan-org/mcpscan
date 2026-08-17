from __future__ import annotations

from mcpscan.capabilities import Capability
from mcpscan.models import (
    ContextualVerdict,
    Finding,
    FindingScope,
    PurposeCategory,
    PurposeProfile,
    PurposeSource,
    Severity,
)
from mcpscan.purpose import load_capability_keywords
from mcpscan.utils.severity import increase_severity

DOWNGRADE_ELIGIBLE = {"MCP-010"}

# =============================================================================
# THE ADJUDICATION TRUST INVARIANT
#
#   Any purpose source may ESCALATE a severity.
#   Only an operator-supplied purpose may DOWNGRADE one.
#
# The asymmetry is the whole design. Escalation needs no trust, because the worst a
# hostile source achieves by escalating is making its own findings look worse. A
# downgrade is a claim that a dangerous capability is fine, so it may only come from
# someone outside the system under test.
#
# OPERATOR_PURPOSE_SOURCES below IS that trust boundary. It, and the source gate in
# _adjudicate_finding, are on the force-flag list: every future change to either is
# Tier C and needs human security review, regardless of green tests. Adding a source to
# this set is a decision about who is allowed to lower a severity. Do not add one to
# make a test pass.
#
# History: d00f8f7 closed the lying-server hole; BRIEF-0.1.1.md bug 1 is the correction
# to a proposed fix that would have reopened it. tests/test_adjudicate_self_declaration.py
# and tests/test_purpose_adjudication_equivalence.py hold both edges.
# =============================================================================

#: Purpose sources the operator controls. ONLY THESE MAY LOWER A SEVERITY.
#:
#: FLAG is --purpose / --purpose-category. INVOCATION is a command line or URL the
#: operator typed at the CLI, which a server cannot forge.
#:
#: Deliberately absent, and both may still escalate:
#:   CONFIG       a command line read from an MCP client config file. It presents as
#:                operator intent, but install snippets are copy-pasted out of
#:                server-authored documentation, so the server may have written it.
#:   SERVER_INFO  the server describing itself. Attacker-controlled outright.
OPERATOR_PURPOSE_SOURCES = {PurposeSource.FLAG, PurposeSource.INVOCATION}


def may_downgrade(profile: PurposeProfile) -> bool:
    """Half of the invariant: only an operator-supplied purpose may lower a severity."""
    return profile.category_source in OPERATOR_PURPOSE_SOURCES


def may_escalate(profile: PurposeProfile) -> bool:
    """The other half: any purpose source may raise one.

    Always True. It exists so the invariant is legible at the call site rather than
    implied by the absence of a check, and so that anyone tempted to gate escalation on
    provenance has to delete a function that says why not to.
    """
    return True


def adjudicate_findings(findings: list[Finding], profile: PurposeProfile) -> list[Finding]:
    return [_adjudicate_finding(finding, profile) for finding in findings]


def _adjudicate_finding(finding: Finding, profile: PurposeProfile) -> Finding:
    original = finding.original_severity or finding.severity
    adjusted = finding.adjusted_severity or original

    if finding.scope is FindingScope.CONFIGURATION:
        # Neither raised nor lowered. A declared purpose cannot make a
        # credential in the environment appropriate, and cannot make an
        # unpinned package into a "hidden capability" either.
        return _updated(
            finding,
            original,
            original,
            ContextualVerdict.UNADJUDICATED,
            "Configuration finding: about how the server is launched, not about a capability "
            "it exposes, so the declared purpose neither excuses nor aggravates it.",
        )

    if (
        profile.category == PurposeCategory.UNKNOWN
        and profile.category_source == PurposeSource.UNKNOWN
    ):
        return _updated(
            finding,
            original,
            adjusted,
            ContextualVerdict.UNADJUDICATED,
            "No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.",
        )

    if finding.capability in profile.expected_capabilities:
        if may_downgrade(profile):
            if _downgrade_eligible(finding, profile):
                return _updated(
                    finding,
                    original,
                    Severity.INFO,
                    ContextualVerdict.EXPECTED_BY_PURPOSE,
                    f"Capability {finding.capability.value} is inherent to declared purpose '{profile.category.value}'. Reported for completeness.",
                )
            return _updated(
                finding,
                original,
                adjusted,
                ContextualVerdict.EXPECTED_BY_PURPOSE,
                f"Capability {finding.capability.value} is inherent to declared purpose '{profile.category.value}', but this check is not downgrade-eligible.",
            )

        # An unconfirmed purpose (CONFIG or SERVER_INFO). Enough to stop mcpscan
        # escalating a capability it has just called expected — the header and the
        # verdict column must not contradict each other — and not enough to lower
        # anything. Severity stays exactly where the check put it.
        return _updated(
            finding,
            original,
            original,
            ContextualVerdict.EXPECTED_UNCONFIRMED,
            f"Capability {finding.capability.value} matches the purpose "
            f"'{profile.category.value}', but that purpose came from "
            f"{_source_description(profile.category_source)}, not from you. Severity is "
            f"unchanged. Pass --purpose-category {profile.category.value} to confirm it.",
        )

    # Escalation path. Open to every source: see the trust invariant above.
    verdict = ContextualVerdict.UNEXPECTED
    reasoning = (
        f"Capability {finding.capability.value} is outside the expected set for "
        f"'{profile.category.value}' but is mentioned in the server's declared text."
    )
    if not _capability_mentioned(finding.capability, profile.declared_text):
        verdict = ContextualVerdict.UNDECLARED
        adjusted = increase_severity(original) if may_escalate(profile) else adjusted
        reasoning = (
            f"Capability {finding.capability.value} is neither expected for "
            f"'{profile.category.value}' nor mentioned anywhere in the declared text. "
            "Possible hidden capability."
        )
    return _updated(finding, original, adjusted, verdict, reasoning)


def _source_description(source: PurposeSource) -> str:
    if source == PurposeSource.CONFIG:
        return "an MCP client config file, which may have been copied from the server's own docs"
    if source == PurposeSource.SERVER_INFO:
        return "the server's own description of itself"
    return source.value


def _downgrade_eligible(finding: Finding, profile: PurposeProfile) -> bool:
    if finding.id in DOWNGRADE_ELIGIBLE:
        return True
    return finding.id == "MCP-021" and profile.category in {
        PurposeCategory.FILESYSTEM,
        PurposeCategory.DATABASE,
    }


def _capability_mentioned(capability: Capability, declared_text: str) -> bool:
    normalized = declared_text.lower()
    return any(keyword in normalized for keyword in load_capability_keywords()[capability])


def _updated(
    finding: Finding,
    original: Severity,
    adjusted: Severity,
    verdict: ContextualVerdict,
    reasoning: str,
) -> Finding:
    return finding.model_copy(
        update={
            "original_severity": original,
            "adjusted_severity": adjusted,
            "contextual_verdict": verdict,
            "verdict_reasoning": reasoning,
        }
    )
