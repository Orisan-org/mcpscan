from __future__ import annotations

from dataclasses import dataclass

from mcpscan.checks.base import Check
from mcpscan.checks.command_injection import CommandInjectionSurfaceCheck
from mcpscan.checks.dangerous_capabilities import DangerousCapabilityExposureCheck
from mcpscan.checks.prompt_injection import ToolDescriptionPromptInjectionCheck
from mcpscan.checks.secrets import SecretExposureInMetadataCheck
from mcpscan.checks.sensitive_exposure import SensitiveDataExposureCheck
from mcpscan.checks.transport import MissingTLSCheck, UnauthenticatedRemoteServerCheck
from mcpscan.checks.typosquat import LookalikeNameCheck
from mcpscan.models import Severity


@dataclass(frozen=True)
class CheckCatalogueEntry:
    id: str
    title: str
    severity: Severity
    status: str
    reference: str


PHASE1_CHECKS: list[Check] = [
    ToolDescriptionPromptInjectionCheck(),
    DangerousCapabilityExposureCheck(),
    SecretExposureInMetadataCheck(),
    SensitiveDataExposureCheck(),
    CommandInjectionSurfaceCheck(),
    UnauthenticatedRemoteServerCheck(),
    MissingTLSCheck(),
    LookalikeNameCheck(),
]

DEFERRED_CHECKS = [
    CheckCatalogueEntry(
        id="MCP-002",
        title="Tool definition drift",
        severity=Severity.HIGH,
        status="deferred",
        reference="OWASP MCP Top 10: Rug pull",
    )
]


def active_checks() -> list[Check]:
    return list(PHASE1_CHECKS)


def check_catalogue() -> list[CheckCatalogueEntry]:
    entries = [
        CheckCatalogueEntry(
            id=check.id,
            title=check.title,
            severity=check.severity,
            status=check.status,
            reference=check.reference,
        )
        for check in PHASE1_CHECKS
    ]
    entries.extend(DEFERRED_CHECKS)
    return sorted(entries, key=lambda item: item.id)
