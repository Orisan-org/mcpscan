from __future__ import annotations

from typing import Any

from mcpscan.connectors.base import Connector
from mcpscan.errors import EnumerationError
from mcpscan.models import ScanContext, ServerInfo, Transport
from mcpscan.normalizer import normalize_prompts, normalize_resources, normalize_tools


class RemoteConnector(Connector):
    async def enumerate(self) -> ScanContext:
        if not self.target.url:
            raise EnumerationError("Missing remote URL.")
        try:
            from mcp import ClientSession
        except ImportError as exc:
            raise EnumerationError(
                "The official mcp Python SDK is required for remote scanning."
            ) from exc

        client_factory = _remote_client_factory(self.target.transport)
        warnings: list[str] = []
        try:
            async with client_factory(self.target.url, headers=self.target.headers) as streams:
                read_stream, write_stream = streams[0], streams[1]
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    tools = await _safe_list(session, "list_tools", "tools/list", warnings)
                    resources = await _safe_list(
                        session, "list_resources", "resources/list", warnings
                    )
                    prompts = await _safe_list(session, "list_prompts", "prompts/list", warnings)
                    return ScanContext(
                        target=self.target,
                        server=_server_info(initialized),
                        tools=normalize_tools(getattr(tools, "tools", tools or [])),
                        resources=normalize_resources(
                            getattr(resources, "resources", resources or [])
                        ),
                        prompts=normalize_prompts(getattr(prompts, "prompts", prompts or [])),
                        warnings=warnings,
                        unauthenticated_enumeration=not bool(self.target.headers),
                    )
        except EnumerationError:
            raise
        except Exception as exc:
            message = str(exc)
            if "401" in message or "403" in message:
                raise EnumerationError(
                    f"Remote MCP server rejected enumeration: {message}"
                ) from exc
            raise EnumerationError(f"Failed to enumerate remote MCP server: {message}") from exc


def _remote_client_factory(transport: Transport) -> Any:
    if transport == Transport.SSE:
        try:
            from mcp.client.sse import sse_client

            return sse_client
        except ImportError as exc:
            raise EnumerationError(
                "SSE remote transport is not available in the installed mcp SDK."
            ) from exc
    try:
        from mcp.client.streamable_http import streamablehttp_client

        return streamablehttp_client
    except ImportError as exc:
        raise EnumerationError(
            "Streamable HTTP transport is not available in the installed mcp SDK."
        ) from exc


async def _safe_list(session: Any, method_name: str, label: str, warnings: list[str]) -> Any:
    try:
        method = getattr(session, method_name)
        return await method()
    except Exception:
        warnings.append(f"{label} failed or not supported")
        return None


def _server_info(initialized: Any) -> ServerInfo:
    data = _to_dict(initialized)
    info = data.get("serverInfo") or data.get("server_info") or {}
    capabilities = data.get("capabilities") or {}
    return ServerInfo(
        name=info.get("name"),
        version=info.get("version"),
        protocol_version=data.get("protocolVersion") or data.get("protocol_version"),
        capabilities=capabilities if isinstance(capabilities, dict) else _to_dict(capabilities),
    )


def _to_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, dict):
        return value
    return {
        key: getattr(value, key)
        for key in dir(value)
        if not key.startswith("_") and not callable(getattr(value, key))
    }
