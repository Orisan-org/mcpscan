from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from mcpscan.connectors.base import Connector
from mcpscan.errors import EnumerationError, exception_summary, unwrap_exception_group
from mcpscan.models import ScanContext, ServerInfo
from mcpscan.normalizer import normalize_prompts, normalize_resources, normalize_tools


class StdioConnector(Connector):
    async def enumerate(self) -> ScanContext:
        try:
            return await asyncio.wait_for(
                self._enumerate(),
                timeout=self.timeout_seconds,
            )
        except TimeoutError as exc:
            raise EnumerationError(
                f"stdio handshake timed out after {self.timeout_seconds:.0f}s. "
                "Cold-start npx/uvx servers can take 30+ seconds on first run. "
                "Retry, or raise --timeout."
            ) from exc

    async def _enumerate(self) -> ScanContext:
        if not self.target.command:
            raise EnumerationError("Missing stdio command.")
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise EnumerationError(
                "The official mcp Python SDK is required for stdio scanning."
            ) from exc

        command = _resolve_executable(self.target.command[0])
        args = self.target.command[1:]
        params = StdioServerParameters(
            command=command,
            args=args,
            env=child_environment(self.target.env),
        )
        warnings: list[str] = []

        try:
            with open(os.devnull, "w", encoding="utf-8") as errlog:
                async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        initialized = await session.initialize()
                        server = _server_info(initialized)
                        tools = await _safe_list(session, "list_tools", "tools/list", warnings)
                        resources = await _safe_list(
                            session, "list_resources", "resources/list", warnings
                        )
                        prompts = await _safe_list(
                            session, "list_prompts", "prompts/list", warnings
                        )
                        return ScanContext(
                            target=self.target,
                            server=server,
                            tools=normalize_tools(getattr(tools, "tools", tools or [])),
                            resources=normalize_resources(
                                getattr(resources, "resources", resources or [])
                            ),
                            prompts=normalize_prompts(getattr(prompts, "prompts", prompts or [])),
                            warnings=warnings,
                        )
        except EnumerationError:
            raise
        except Exception as exc:
            command = self.target.raw or " ".join(self.target.command or [])
            raise EnumerationError(_stdio_failure_message(command, exc)) from exc


#: Parent environment variables forwarded to a scanned server. Mirrors the mcp SDK's
#: own allowlist. Everything else in os.environ is withheld deliberately -- mcpscan
#: launches servers precisely because they might be malicious, and a scanned server has
#: no business receiving the operator's cloud keys, tokens or CI secrets.
INHERITED_ENV_VARS = (
    (
        "APPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "USERNAME",
        "USERPROFILE",
    )
    if sys.platform == "win32"
    else ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER")
)


def child_environment(configured_env: dict[str, str] | None) -> dict[str, str]:
    """The environment a scanned stdio server is launched with.

    A safe subset of the parent environment, with any config-supplied values overlaid on
    top (config wins on conflict). Computed here rather than left to the SDK's default:
    0.1.0 passed ``env=self.target.env or None`` and relied on ``stdio_client`` to
    substitute its own defaults for ``None``. That worked, but it made mcpscan's child
    environment a property of whichever SDK version got resolved, which is the shape of
    bug 3. It is now mcpscan's decision and mcpscan's test.

    Note this is NOT ``os.environ``. Full inheritance would forward every secret the
    operator happens to have exported into a server that mcpscan is running *because it
    may be hostile*. Values are never echoed: reports carry env names and counts only.
    """
    env = {
        name: value
        for name in INHERITED_ENV_VARS
        if (value := os.environ.get(name)) is not None and not value.startswith("()")
    }
    env.update(configured_env or {})
    return env


def _stdio_failure_message(command: str, exc: BaseException) -> str:
    """Turn a raw stdio failure (e.g. 'McpError: Connection closed') into a human
    message that names the server command and the likely cause. Error text only --
    detection, scoring, and verdicts are untouched."""
    summary = exception_summary(exc)
    root = unwrap_exception_group(exc)
    name = command.strip() if command else "(unknown command)"
    closed_early = (
        isinstance(root, FileNotFoundError)
        or "connection closed" in summary.lower()
        or "closed" in summary.lower()
    )
    if closed_early:
        return (
            f"Could not start MCP server: `{name}`. "
            "The process exited before the MCP handshake completed. Likely causes: the "
            "command failed to start (executable not found), or the package could not be "
            "resolved or installed (for npx/uvx, check the package name). "
            f"Run the command yourself to see the underlying error. [details: {summary}]"
        )
    return f"Failed to enumerate MCP server `{name}`: {summary}"


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
        instructions=data.get("instructions") or info.get("instructions"),
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
    result: dict[str, Any] = {}
    for key in dir(value):
        if key.startswith("_"):
            continue
        item = getattr(value, key)
        if not callable(item):
            result[key] = item
    return result


def _resolve_executable(command: str) -> str:
    if sys.platform != "win32" or os.path.splitext(command)[1]:
        return command
    if command.lower() in {"npx", "npm", "pnpm", "yarn"}:
        return f"{command}.cmd"
    return command
