import pytest

from mcpscan.errors import TargetError
from mcpscan.models import TargetKind, Transport
from mcpscan.target import parse_headers, resolve_target


def test_parses_stdio_command() -> None:
    target = resolve_target(None, command="python server.py", transport=None)

    assert target.kind == TargetKind.COMMAND
    assert target.transport == Transport.STDIO
    assert target.command == ["python", "server.py"]


def test_parses_https_url() -> None:
    target = resolve_target("https://example.com/mcp", command=None, transport=None)

    assert target.kind == TargetKind.URL
    assert target.transport == Transport.HTTP
    assert target.url == "https://example.com/mcp"


def test_parses_http_url() -> None:
    target = resolve_target("http://localhost:8000/mcp", command=None, transport=Transport.SSE)

    assert target.transport == Transport.SSE


def test_parses_repeated_headers() -> None:
    assert parse_headers(["Authorization: Bearer fake", "X-Test: yes"]) == {
        "Authorization": "Bearer fake",
        "X-Test": "yes",
    }


def test_rejects_bad_header() -> None:
    with pytest.raises(TargetError):
        parse_headers(["bad"])


def test_rejects_invalid_target() -> None:
    with pytest.raises(TargetError):
        resolve_target("server.py", command=None, transport=None)
