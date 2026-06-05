from mcpscan.connectors.remote import RemoteConnector
from mcpscan.connectors.stdio import StdioConnector
from mcpscan.models import ScanContext, ScanTarget, TargetKind


async def enumerate_target(target: ScanTarget, timeout_seconds: float = 20.0) -> ScanContext:
    connector = (
        StdioConnector(target, timeout_seconds)
        if target.kind == TargetKind.COMMAND
        else RemoteConnector(target, timeout_seconds)
    )
    return await connector.enumerate()
