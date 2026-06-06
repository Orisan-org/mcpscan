from mcpscan.checks.dangerous_capabilities import DangerousCapabilityExposureCheck
from mcpscan.models import ExposedTool, ScanContext, Severity
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


def test_detects_fetch_url_input_as_network_capability() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="fetch",
                description="Fetches a URL from the internet.",
                input_schema={"properties": {"url": {"type": "string"}}},
            )
        ],
    )

    findings = DangerousCapabilityExposureCheck().run(ctx)

    assert findings[0].id == "MCP-010"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].target == "fetch"
    assert findings[0].payload_stored is False
    assert "outbound network request capability" in findings[0].evidence


def test_detects_common_network_tool_shapes() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="http_request", input_schema={"properties": {"url": {"type": "string"}}}
            ),
            ExposedTool(
                name="download_file",
                input_schema={"properties": {"url": {"type": "string"}}},
            ),
            ExposedTool(name="crawl", input_schema={"properties": {"url": {"type": "string"}}}),
            ExposedTool(
                name="scrape_url",
                input_schema={"properties": {"url": {"type": "string"}}},
            ),
            ExposedTool(
                name="browser_navigate",
                input_schema={"properties": {"url": {"type": "string"}}},
            ),
        ],
    )

    findings = DangerousCapabilityExposureCheck().run(ctx)

    assert {finding.target for finding in findings} == {
        "http_request",
        "download_file",
        "crawl",
        "scrape_url",
        "browser_navigate",
    }
    assert all(finding.severity == Severity.HIGH for finding in findings)


def test_constrained_fetch_url_input_is_medium() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="fetch",
                description="Fetch approved documentation URLs.",
                input_schema={
                    "properties": {
                        "url": {
                            "type": "string",
                            "enum": ["https://docs.example.test/index.html"],
                        }
                    }
                },
            )
        ],
    )

    findings = DangerousCapabilityExposureCheck().run(ctx)

    assert findings[0].severity == Severity.MEDIUM


def test_ignores_memory_and_retrieval_query_tools() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="search_nodes",
                description="Search knowledge graph memory nodes.",
                input_schema={"properties": {"query": {"type": "string"}}},
            ),
            ExposedTool(
                name="find_documents",
                description="Find matching documentation.",
                input_schema={"properties": {"query": {"type": "string"}}},
            ),
            ExposedTool(
                name="lookup",
                description="Lookup memory records.",
                input_schema={"properties": {"query": {"type": "string"}}},
            ),
        ],
    )

    assert DangerousCapabilityExposureCheck().run(ctx) == []


def test_ignores_normal_search() -> None:
    assert DangerousCapabilityExposureCheck().run(benign_context()) == []
