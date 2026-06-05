from mcpscan.checks.transport import MissingTLSCheck, UnauthenticatedRemoteServerCheck
from mcpscan.models import ScanContext, Severity
from tests.helpers import url_target


def test_flags_non_local_http_as_high() -> None:
    ctx = ScanContext(target=url_target("http://example.com/mcp"))

    findings = MissingTLSCheck().run(ctx)

    assert findings[0].severity == Severity.HIGH


def test_flags_localhost_http_as_medium() -> None:
    ctx = ScanContext(target=url_target("http://localhost:8000/mcp"))

    findings = MissingTLSCheck().run(ctx)

    assert findings[0].severity == Severity.MEDIUM


def test_ignores_https() -> None:
    ctx = ScanContext(target=url_target("https://example.com/mcp"))

    assert MissingTLSCheck().run(ctx) == []


def test_remote_no_headers_and_enumeration_success_flags_auth() -> None:
    ctx = ScanContext(
        target=url_target("https://example.com/mcp"), unauthenticated_enumeration=True
    )

    assert UnauthenticatedRemoteServerCheck().run(ctx)


def test_remote_with_headers_does_not_flag_auth() -> None:
    ctx = ScanContext(
        target=url_target("https://example.com/mcp", headers={"Authorization": "Bearer fake"}),
        unauthenticated_enumeration=True,
    )

    assert UnauthenticatedRemoteServerCheck().run(ctx) == []
