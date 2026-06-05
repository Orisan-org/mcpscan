from abc import ABC, abstractmethod

from mcpscan.models import Finding, ScanContext, Severity


class Check(ABC):
    id: str
    title: str
    severity: Severity
    reference: str
    status: str = "active"

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]: ...

    def finding(
        self,
        *,
        severity: Severity | None = None,
        target: str,
        evidence: str,
        remediation: str,
        metadata: dict | None = None,
    ) -> Finding:
        return Finding(
            id=self.id,
            title=self.title,
            severity=severity or self.severity,
            target=target,
            evidence=evidence,
            remediation=remediation,
            reference=self.reference,
            payload_stored=False,
            metadata=metadata or {},
        )
