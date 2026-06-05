from __future__ import annotations

import shlex
from collections.abc import Iterable
from urllib.parse import urlparse

from mcpscan.errors import TargetError
from mcpscan.models import ScanTarget, TargetKind, Transport


def parse_headers(header_values: Iterable[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in header_values or []:
        if ":" not in value:
            raise TargetError(f"Invalid header {value!r}; expected 'Name: Value'.")
        key, header_value = value.split(":", 1)
        key = key.strip()
        header_value = header_value.strip()
        if not key or not header_value:
            raise TargetError(f"Invalid header {value!r}; expected 'Name: Value'.")
        headers[key] = header_value
    return headers


def resolve_target(
    target: str | None,
    *,
    command: str | None,
    transport: Transport | None,
    headers: Iterable[str] | None = None,
) -> ScanTarget:
    parsed_headers = parse_headers(headers)
    if command:
        if target and target.startswith(("http://", "https://")):
            raise TargetError("--command cannot be combined with a remote URL target.")
        try:
            command_parts = shlex.split(command)
        except ValueError as exc:
            raise TargetError(f"Invalid command: {exc}") from exc
        if not command_parts:
            raise TargetError("--command cannot be empty.")
        if transport and transport != Transport.STDIO:
            raise TargetError("--command only supports --transport stdio.")
        return ScanTarget(
            raw=command,
            kind=TargetKind.COMMAND,
            transport=Transport.STDIO,
            command=command_parts,
            headers={},
        )

    if not target:
        raise TargetError(
            "Provide a URL target or use --command. Example: mcpscan scan --command 'python server.py'"
        )

    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise TargetError("Target must be http(s) URL unless --command is provided.")
    resolved_transport = transport or Transport.HTTP
    if resolved_transport == Transport.STDIO:
        raise TargetError("URL targets cannot use --transport stdio.")
    return ScanTarget(
        raw=target,
        kind=TargetKind.URL,
        transport=resolved_transport,
        url=target,
        headers=parsed_headers,
    )
