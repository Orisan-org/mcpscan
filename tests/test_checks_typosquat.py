from mcpscan.checks.known_mcp_names import KNOWN_MCP_SERVER_NAMES
from mcpscan.checks.typosquat import LookalikeNameCheck
from mcpscan.models import ExposedTool, ScanContext, ServerInfo
from tests.helpers import command_target


def test_known_name_seed_list_has_expected_coverage() -> None:
    assert len(KNOWN_MCP_SERVER_NAMES) == 31
    assert "filesystem" in KNOWN_MCP_SERVER_NAMES
    assert "playwright" in KNOWN_MCP_SERVER_NAMES
    assert "sequential-thinking" in KNOWN_MCP_SERVER_NAMES


def test_exact_known_name_no_finding() -> None:
    ctx = ScanContext(target=command_target(), server=ServerInfo(name="github"))

    assert LookalikeNameCheck().run(ctx) == []


def test_githab_flags() -> None:
    ctx = ScanContext(target=command_target(), server=ServerInfo(name="githab"))

    assert LookalikeNameCheck().run(ctx)


def test_filesytem_flags() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="filesytem")])

    assert LookalikeNameCheck().run(ctx)


def test_scoped_package_typo_flags() -> None:
    ctx = ScanContext(
        target=command_target(),
        server=ServerInfo(name="@modelcontextprotocol/server-filesytem"),
    )

    findings = LookalikeNameCheck().run(ctx)

    assert findings
    assert findings[0].target == "@modelcontextprotocol/server-filesytem"
    assert findings[0].payload_stored is False


def test_scoped_exact_package_name_no_finding() -> None:
    ctx = ScanContext(
        target=command_target(),
        server=ServerInfo(name="@modelcontextprotocol/server-filesystem"),
    )

    assert LookalikeNameCheck().run(ctx) == []


def test_case_normalization_no_finding_for_exact_name() -> None:
    ctx = ScanContext(target=command_target(), server=ServerInfo(name="GitHub"))

    assert LookalikeNameCheck().run(ctx) == []


def test_hyphen_underscore_normalization_is_explicit() -> None:
    ctx = ScanContext(target=command_target(), server=ServerInfo(name="brave_search"))

    assert LookalikeNameCheck().run(ctx) == []


def test_no_duplicate_findings_for_equivalent_normalized_names() -> None:
    ctx = ScanContext(
        target=command_target(),
        server=ServerInfo(name="filesytem"),
        tools=[ExposedTool(name="@modelcontextprotocol/server-filesytem")],
    )

    findings = LookalikeNameCheck().run(ctx)

    assert len(findings) == 1


def test_random_internal_tool_no_finding() -> None:
    ctx = ScanContext(target=command_target(), tools=[ExposedTool(name="random_internal_tool")])

    assert LookalikeNameCheck().run(ctx) == []
