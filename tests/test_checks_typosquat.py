from mcpscan.checks.typosquat import LookalikeNameCheck
from mcpscan.models import ExposedTool, ScanContext, ServerInfo
from tests.helpers import command_target


def test_exact_known_name_no_finding() -> None:
    ctx = ScanContext(target=command_target(), server=ServerInfo(name="github"))

    assert LookalikeNameCheck().run(ctx) == []


def test_githab_flags() -> None:
    ctx = ScanContext(target=command_target(), server=ServerInfo(name="githab"))

    assert LookalikeNameCheck().run(ctx)


def test_filesytem_flags() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="filesytem")])

    assert LookalikeNameCheck().run(ctx)


def test_random_internal_tool_no_finding() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="random_internal_tool")])

    assert LookalikeNameCheck().run(ctx) == []
