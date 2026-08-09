from __future__ import annotations

from mcpscan.capabilities import Capability
from mcpscan.models import (
    ContextualVerdict,
    Finding,
    PurposeCategory,
    PurposeProfile,
    PurposeSource,
    Severity,
)
from mcpscan.purpose import load_capability_keywords
from mcpscan.utils.severity import increase_severity

DOWNGRADE_ELIGIBLE = {"MCP-010"}

#: Purpose sources the operator controls. Only these may lower a severity.
#:
#: FLAG is --purpose / --purpose-category. INVOCATION is the command line or URL the
#: operator typed, which a server cannot forge. SERVER_INFO is deliberately absent: a
#: server describing itself is attacker-controlled input, and letting it downgrade its
#: own findings is the lying-server hole closed in d00f8f7. See
#: tests/test_adjudicate_self_declaration.py.
OPERATOR_PURPOSE_SOURCES = {PurposeSource.FLAG, PurposeSource.INVOCATION}


def adjudicate_findings(findings: list[Finding], profile: PurposeProfile) -> list[Finding]:
    return [_adjudicate_finding(finding, profile) for finding in findings]


def _adjudicate_finding(finding: Finding, profile: PurposeProfile) -> Finding:
    original = finding.original_severity or finding.severity
    adjusted = finding.adjusted_severity or original

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
        if profile.category_source in OPERATOR_PURPOSE_SOURCES:
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

        # The purpose came from the server's own account of itself. That is enough to
        # stop mcpscan escalating a capability it has just called expected — the header
        # and the verdict column must not contradict each other — but it is not enough
        # to lower anything. Severity stays exactly where the check put it.
        return _updated(
            finding,
            original,
            original,
            ContextualVerdict.EXPECTED_BY_SELF_DECLARATION,
            f"Capability {finding.capability.value} matches the purpose '{profile.category.value}' "
            "that this server declares about itself. Self-declared purpose is not "
            "operator-confirmed, so severity is unchanged. Pass --purpose-category "
            f"{profile.category.value} to confirm it.",
        )

    verdict = ContextualVerdict.UNEXPECTED
    reasoning = (
        f"Capability {finding.capability.value} is outside the expected set for "
        f"'{profile.category.value}' but is mentioned in the server's declared text."
    )
    if not _capability_mentioned(finding.capability, profile.declared_text):
        verdict = ContextualVerdict.UNDECLARED
        adjusted = increase_severity(original)
        reasoning = (
            f"Capability {finding.capability.value} is neither expected for "
            f"'{profile.category.value}' nor mentioned anywhere in the declared text. "
            "Possible hidden capability."
        )
    return _updated(finding, original, adjusted, verdict, reasoning)


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
