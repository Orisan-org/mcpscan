from abc import ABC, abstractmethod

from mcpscan.capabilities import Capability, owasp_reference
from mcpscan.models import Finding, ScanContext, Severity
from mcpscan.tiers import SURFACE_TIERS, EvidenceTier


class Check(ABC):
    id: str
    title: str
    severity: Severity
    default_capability: Capability = Capability.OTHER
    owasp_mcp: str
    status: str = "active"

    #: Evidence tiers that supply this check's inputs.
    #:
    #: Defaults to the tiers that carry a tool surface, because that is what
    #: every check written before tiers existed reads. A check that works from
    #: config alone must say so explicitly — the safe default is to be skipped
    #: and reported as not run, never to run against absent input and return
    #: nothing.
    requires: frozenset[EvidenceTier] = SURFACE_TIERS

    @property
    def reference(self) -> str:
        return owasp_reference(self.owasp_mcp)

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]: ...

    def finding(
        self,
        *,
        severity: Severity | None = None,
        capability: Capability | None = None,
        owasp_mcp: str | None = None,
        target: str,
        evidence: str,
        remediation: str,
        metadata: dict | None = None,
    ) -> Finding:
        finding_owasp = owasp_mcp or self.owasp_mcp
        return Finding(
            id=self.id,
            title=self.title,
            severity=severity or self.severity,
            capability=capability or self.default_capability,
            owasp_mcp=finding_owasp,
            target=target,
            evidence=evidence,
            remediation=remediation,
            reference=owasp_reference(finding_owasp),
            payload_stored=False,
            metadata=metadata or {},
        )
