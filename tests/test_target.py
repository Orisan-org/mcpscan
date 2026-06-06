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


def test_remote_headers_are_preserved() -> None:
    target = resolve_target(
        "https://example.com/mcp",
        command=None,
        transport=None,
        headers=["Authorization: Bearer fake"],
    )

    assert target.headers == {"Authorization": "Bearer fake"}


def test_rejects_headers_for_stdio_command() -> None:
    with pytest.raises(TargetError, match="--header is only supported"):
        resolve_target(
            None,
            command="python server.py",
            transport=None,
            headers=["Authorization: Bearer fake"],
        )


def test_rejects_nonexistent_local_path_with_config_message() -> None:
    with pytest.raises(TargetError, match="Local config/path scanning is not supported"):
        resolve_target("/tmp/does-not-exist", command=None, transport=None)


def test_rejects_existing_mcp_json_with_config_message(tmp_path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text("{}", encoding="utf-8")

    with pytest.raises(TargetError, match="Local config/path scanning is not supported"):
        resolve_target(str(config), command=None, transport=None)


def test_rejects_path_like_value_with_config_message() -> None:
    with pytest.raises(TargetError, match="Local config/path scanning is not supported"):
        resolve_target("./mcp.json", command=None, transport=None)
