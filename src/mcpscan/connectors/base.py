from abc import ABC, abstractmethod

from mcpscan.models import ScanContext, ScanTarget


class Connector(ABC):
    def __init__(self, target: ScanTarget, timeout_seconds: float = 20.0) -> None:
        self.target = target
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    async def enumerate(self) -> ScanContext: ...
