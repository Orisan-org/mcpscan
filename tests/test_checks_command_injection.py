from mcpscan.checks.command_injection import CommandInjectionSurfaceCheck
from mcpscan.models import ExposedTool, ScanContext, Severity
from tests.helpers import command_target


def test_detects_freeform_command_parameter() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="run",
                description="Run shell command.",
                input_schema={"properties": {"command": {"type": "string"}}},
            )
        ],
    )

    findings = CommandInjectionSurfaceCheck().run(ctx)

    assert findings[0].severity == Severity.HIGH
    assert findings[0].payload_stored is False
    assert "commands or code" in findings[0].evidence


def test_constrained_enum_command_is_not_high() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="run",
                description="Run command.",
                input_schema={
                    "properties": {
                        "command": {"type": "string", "enum": ["npm_test", "git_status"]}
                    }
                },
            )
        ],
    )

    findings = CommandInjectionSurfaceCheck().run(ctx)

    assert findings[0].severity == Severity.MEDIUM


def test_ignores_search_query() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="search",
                description="Search docs.",
                input_schema={"properties": {"query": {"type": "string"}}},
            )
        ],
    )

    assert CommandInjectionSurfaceCheck().run(ctx) == []


def test_ignores_memory_search_nodes_query() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="search_nodes",
                description="Search knowledge graph memory nodes.",
                input_schema={"properties": {"query": {"type": "string"}}},
            )
        ],
    )

    assert CommandInjectionSurfaceCheck().run(ctx) == []


def test_ignores_retrieval_query_tools() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="find_documents",
                description="Find relevant documentation.",
                input_schema={"properties": {"query": {"type": "string"}}},
            ),
            ExposedTool(
                name="lookup",
                description="Lookup an item by search text.",
                input_schema={"properties": {"query": {"type": "string"}}},
            ),
            ExposedTool(
                name="query_memory",
                description="Retrieve memory records from the knowledge graph.",
                input_schema={"properties": {"query": {"type": "string"}}},
            ),
        ],
    )

    assert CommandInjectionSurfaceCheck().run(ctx) == []


def test_detects_execute_shell_cmd_parameter() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="execute_shell",
                description="Execute a shell command.",
                input_schema={"properties": {"cmd": {"type": "string"}}},
            )
        ],
    )

    findings = CommandInjectionSurfaceCheck().run(ctx)

    assert findings[0].severity == Severity.HIGH
    assert findings[0].payload_stored is False


def test_detects_eval_code_parameter() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="eval_code",
                description="Evaluate Python code.",
                input_schema={"properties": {"code": {"type": "string"}}},
            )
        ],
    )

    findings = CommandInjectionSurfaceCheck().run(ctx)

    assert findings[0].severity == Severity.HIGH
    assert "commands or code" in findings[0].evidence


def test_detects_script_and_code_execution_parameters() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="run_script",
                description="Run a script.",
                input_schema={"properties": {"script": {"type": "string"}}},
            ),
            ExposedTool(
                name="execute_code",
                description="Execute code.",
                input_schema={"properties": {"code": {"type": "string"}}},
            ),
        ],
    )

    findings = CommandInjectionSurfaceCheck().run(ctx)

    assert {finding.target for finding in findings} == {"run_script", "execute_code"}
    assert all(finding.severity == Severity.HIGH for finding in findings)


def test_detects_execute_sql_query_only_with_database_semantics() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="execute_sql",
                description="Execute SQL against the database.",
                input_schema={"properties": {"query": {"type": "string"}}},
            )
        ],
    )

    findings = CommandInjectionSurfaceCheck().run(ctx)

    assert findings[0].severity == Severity.HIGH
    assert "SQL or database queries" in findings[0].evidence


def test_generic_query_tool_does_not_trigger_sql_detection() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="query_memory",
                description="Query memory records.",
                input_schema={"properties": {"query": {"type": "string"}}},
            )
        ],
    )

    assert CommandInjectionSurfaceCheck().run(ctx) == []
