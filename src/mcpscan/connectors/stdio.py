from __future__ import annotations

import asyncio
import errno
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
                _handshake_timeout_message(
                    self.target.raw or " ".join(self.target.command or []),
                    self.timeout_seconds,
                )
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


# Slice G of BRIEF-0.1.1.md. `Connection closed` covered three different failures:
# a command that never started, a process that started and died, and a process that
# started and was still working when the timeout expired. Those need three different
# responses from the operator, and collapsing them cost this release a wrong diagnosis
# — bug 2 was filed against environment handling on the strength of that wording, and
# withdrawn once the process turned out to be fine and merely slow.
#
# Error text only. Detection, scoring and verdicts are untouched by this module.
STAGE_SPAWN = "spawn"
STAGE_HANDSHAKE = "handshake"


def _command_label(command: str) -> str:
    """The command as the operator gave it. Config targets arrive pre-redacted."""
    return command.strip() if command and command.strip() else "(unknown command)"


def _stdio_failure_message(command: str, exc: BaseException) -> str:
    summary = exception_summary(exc)
    root = unwrap_exception_group(exc)
    name = _command_label(command)

    if _is_spawn_failure(root):
        return (
            f"MCP server failed at the {STAGE_SPAWN} stage: the command never started.\n"
            f"  command: {name}\n"
            "The executable could not be run. Check the name, and that it is on PATH. "
            "No server code was executed. "
            f"[details: {summary}]"
        )

    if "closed" in summary.lower():
        return (
            f"MCP server failed at the {STAGE_HANDSHAKE} stage: the process started, "
            "then exited before completing the MCP handshake.\n"
            f"  command: {name}\n"
            "This is not a missing executable and not a timeout — the process ran and "
            "stopped. Run the command yourself to see what it printed. "
            f"[details: {summary}]"
        )

    # The process ran and answered, but not with MCP. 0.1.0 reported this as "Could not
    # start MCP server ... the command failed to start", which is a wrong diagnosis of a
    # process that started perfectly well — the same collapsing this slice exists to end.
    return (
        f"MCP server failed at the {STAGE_HANDSHAKE} stage: the process started but did "
        "not speak MCP.\n"
        f"  command: {name}\n"
        "It produced output the MCP handshake could not parse. Check that this command "
        "is an MCP server, and not a wrapper that prints to stdout. "
        f"[details: {summary}]"
    )


def _handshake_timeout_message(command: str, timeout_seconds: float) -> str:
    return (
        f"MCP server failed at the {STAGE_HANDSHAKE} stage: the process started but did "
        f"not complete the MCP handshake within {timeout_seconds:.0f}s.\n"
        f"  command: {_command_label(command)}\n"
        "The process was alive and had not answered. Launchers that fetch on first use "
        "(npx, uvx) can spend the whole window downloading the package. Retry once the "
        "download is warm, or raise --timeout."
    )


def _is_spawn_failure(root: BaseException) -> bool:
    """True when the OS refused to start the command at all."""
    if isinstance(root, (FileNotFoundError, PermissionError, NotADirectoryError)):
        return True
    return isinstance(root, OSError) and root.errno in {errno.ENOENT, errno.EACCES, errno.ENOTDIR}


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
