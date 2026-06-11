from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mcpscan.errors import TargetError
from mcpscan.models import ConfiguredServer, SkippedConfiguredServer, Transport


class LoadedConfig(BaseModel):
    paths: list[str] = Field(default_factory=list)
    servers: list[ConfiguredServer] = Field(default_factory=list)
    skipped: list[SkippedConfiguredServer] = Field(default_factory=list)


def discover_config_paths() -> list[Path]:
    candidates = [
        Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
        Path.home() / ".config/Claude/claude_desktop_config.json",
        Path.cwd() / ".mcp.json",
        Path.home() / ".claude.json",
        Path.cwd() / ".cursor/mcp.json",
        Path.home() / ".cursor/mcp.json",
        Path.home() / ".codeium/windsurf/mcp_config.json",
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "Claude/claude_desktop_config.json")

    seen: set[Path] = set()
    paths: list[Path] = []
    for candidate in candidates:
        path = candidate.expanduser()
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            paths.append(path)
    return paths


def load_mcp_configs(config_path: Path | None = None) -> LoadedConfig:
    paths = [_validate_explicit_path(config_path)] if config_path else discover_config_paths()
    if not paths:
        raise TargetError(
            "No MCP config files found. Pass an explicit path, for example: mcpscan scan-config ./mcp.json"
        )

    loaded = LoadedConfig(paths=[str(path) for path in paths])
    for path in paths:
        _load_one(path, loaded)

    if not loaded.servers and not loaded.skipped:
        raise TargetError("No MCP server entries found in selected config file(s).")
    return loaded


def _validate_explicit_path(path: Path | None) -> Path:
    if path is None:
        raise TargetError("Config path is required.")
    expanded = path.expanduser()
    if not expanded.exists():
        raise TargetError(f"Config file does not exist: {expanded}")
    if expanded.is_dir():
        raise TargetError(f"Config path is a directory, expected a JSON file: {expanded}")
    return expanded


def _load_one(path: Path, loaded: LoadedConfig) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TargetError(f"Invalid JSON in config file {path}: {exc.msg}") from exc
    except OSError as exc:
        raise TargetError(f"Could not read config file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise TargetError(f"MCP config must be a JSON object: {path}")
    mcp_servers = data.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        raise TargetError(f"MCP config must contain a top-level 'mcpServers' object: {path}")

    for name, entry in mcp_servers.items():
        server_name = str(name)
        parsed = _parse_server_entry(server_name, str(path), entry)
        if isinstance(parsed, ConfiguredServer):
            loaded.servers.append(parsed)
        else:
            loaded.skipped.append(parsed)


def _parse_server_entry(
    name: str, source_path: str, entry: Any
) -> ConfiguredServer | SkippedConfiguredServer:
    if not isinstance(entry, dict):
        return _skipped(name, source_path, "entry is not an object")
    env, env_error = _parse_string_map(entry.get("env", {}), "env")
    env_names = sorted(env)
    if entry.get("disabled") is True:
        return _skipped(name, source_path, "disabled=true", env_names)
    if env_error:
        return _skipped(name, source_path, env_error)

    command = entry.get("command")
    if isinstance(command, str) and command.strip():
        args = entry.get("args", [])
        if args is None:
            args = []
        if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
            return _skipped(name, source_path, "args must be a list of strings", env_names)
        return ConfiguredServer(
            name=name,
            source_path=source_path,
            transport=Transport.STDIO,
            command=[command, *args],
            env=env,
            env_names=env_names,
        )

    url = entry.get("url")
    if isinstance(url, str) and url.startswith(("http://", "https://")):
        headers, headers_error = _parse_string_map(entry.get("headers", {}), "headers")
        if headers_error:
            return _skipped(name, source_path, headers_error, env_names)
        return ConfiguredServer(
            name=name,
            source_path=source_path,
            transport=Transport.HTTP,
            url=url,
            headers=headers,
            env_names=env_names,
        )

    return _skipped(name, source_path, "missing supported command or url", env_names)


def _parse_string_map(value: Any, label: str) -> tuple[dict[str, str], str | None]:
    if value in ({}, None):
        return {}, None
    if not isinstance(value, dict):
        return {}, f"{label} must be an object"
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        return {}, f"{label} must contain only string keys and values"
    return dict(value), None


def _skipped(
    name: str,
    source_path: str,
    reason: str,
    env_names: list[str] | None = None,
) -> SkippedConfiguredServer:
    return SkippedConfiguredServer(
        name=name,
        source_path=source_path,
        reason=reason,
        env_names=env_names or [],
    )
