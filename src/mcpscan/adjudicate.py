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

DOWNGRADE_ELIGIBLE_ALWAYS = {"MCP-010", "MCP-030"}


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
    if finding.id in DOWNGRADE_ELIGIBLE_ALWAYS:
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
