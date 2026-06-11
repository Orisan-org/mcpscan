from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpscan.config_loader import discover_config_paths, load_mcp_configs
from mcpscan.errors import TargetError
from mcpscan.models import Transport


def write_config(tmp_path, payload: dict):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_stdio_and_remote_entries_without_env_values(tmp_path) -> None:
    path = write_config(
        tmp_path,
        {
            "mcpServers": {
                "stdio": {
                    "command": "python",
                    "args": ["server.py"],
                    "env": {"SECRET": "hunter2"},
                },
                "remote": {
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": "Bearer fake"},
                },
            }
        },
    )

    loaded = load_mcp_configs(path)

    assert [server.name for server in loaded.servers] == ["stdio", "remote"]
    assert loaded.servers[0].transport == Transport.STDIO
    assert loaded.servers[0].command == ["python", "server.py"]
    assert loaded.servers[0].env_names == ["SECRET"]
    assert loaded.servers[1].transport == Transport.HTTP
    assert "hunter2" not in loaded.model_dump_json()
    assert "Bearer fake" not in loaded.model_dump_json()


def test_loader_skips_disabled_and_malformed_entries(tmp_path) -> None:
    path = write_config(
        tmp_path,
        {
            "mcpServers": {
                "disabled": {"command": "python", "disabled": True},
                "bad-args": {"command": "python", "args": [1]},
                "good": {"command": "python"},
            }
        },
    )

    loaded = load_mcp_configs(path)

    assert [server.name for server in loaded.servers] == ["good"]
    assert {server.name for server in loaded.skipped} == {"disabled", "bad-args"}


def test_loader_missing_file_is_input_error(tmp_path) -> None:
    with pytest.raises(TargetError, match="does not exist"):
        load_mcp_configs(tmp_path / "missing.json")


def test_loader_invalid_json_is_input_error(tmp_path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(TargetError, match="Invalid JSON"):
        load_mcp_configs(path)


def test_loader_requires_mcp_servers(tmp_path) -> None:
    path = write_config(tmp_path, {"servers": {}})

    with pytest.raises(TargetError, match="mcpServers"):
        load_mcp_configs(path)


def test_discovers_project_and_home_config_paths(tmp_path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    project_config = project / ".mcp.json"
    project_config.write_text('{"mcpServers": {}}', encoding="utf-8")
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    cursor_config = cursor_dir / "mcp.json"
    cursor_config.write_text('{"mcpServers": {}}', encoding="utf-8")

    monkeypatch.chdir(project)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    paths = discover_config_paths()

    assert project_config in paths
    assert cursor_config in paths
