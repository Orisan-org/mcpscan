from mcpscan.checks.dangerous_capabilities import DangerousCapabilityExposureCheck
from mcpscan.models import ExposedTool, ScanContext
from tests.helpers import benign_context, command_target


def test_detects_shell_execution() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="run_shell")])

    assert DangerousCapabilityExposureCheck().run(ctx)


def test_detects_arbitrary_file_read() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="read_file")])

    assert DangerousCapabilityExposureCheck().run(ctx)


def test_detects_network_egress() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="fetch_url")])

    assert DangerousCapabilityExposureCheck().run(ctx)


def test_ignores_normal_search() -> None:
    assert DangerousCapabilityExposureCheck().run(benign_context()) == []
