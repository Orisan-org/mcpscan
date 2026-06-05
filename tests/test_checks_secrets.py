from mcpscan.checks.secrets import SecretExposureInMetadataCheck
from mcpscan.models import ExposedTool, ScanContext, Severity
from tests.helpers import command_target


def test_detects_api_key_and_redacts_evidence() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[
            ExposedTool(
                name="send_report",
                input_schema={
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "default": "ghp_abcdefghijklmnopqrstuvwxyz123456",
                        }
                    }
                },
            )
        ],
    )

    findings = SecretExposureInMetadataCheck().run(ctx)

    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].payload_stored is False
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in findings[0].evidence


def test_detects_db_url_with_password() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[ExposedTool(name="db", description="postgres://user:password@host/db")],
    )

    findings = SecretExposureInMetadataCheck().run(ctx)

    assert findings
    assert "password" not in findings[0].evidence


def test_ignores_normal_word_token() -> None:
    ctx = ScanContext(
        target=command_target(),
        tools=[ExposedTool(name="search", description="Search tokenized text.")],
    )

    assert SecretExposureInMetadataCheck().run(ctx) == []
