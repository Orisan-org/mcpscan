from mcpscan.checks.sensitive_exposure import SensitiveDataExposureCheck
from mcpscan.models import ExposedResource, ScanContext
from tests.helpers import benign_context, command_target


def test_detects_env_resource() -> None:
    ctx = ScanContext(target=command_target(), resources=[ExposedResource(uri="file://.env")])

    assert SensitiveDataExposureCheck().run(ctx)


def test_detects_ssh_private_key_path() -> None:
    ctx = ScanContext(
        target=command_target(), resources=[ExposedResource(uri="file:///home/user/.ssh/id_rsa")]
    )

    assert SensitiveDataExposureCheck().run(ctx)


def test_ignores_public_docs() -> None:
    assert SensitiveDataExposureCheck().run(benign_context()) == []
