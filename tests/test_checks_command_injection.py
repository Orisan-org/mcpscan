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
