from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from mcpscan.config_loader import load_mcp_configs
from mcpscan.errors import EnumerationError, TargetError
from mcpscan.models import (
    ConfigScanResult,
    ConfigScanSummary,
    ConfigServerFailure,
    ConfigServerResult,
    ConfiguredServer,
    ScanTarget,
    SkippedConfiguredServer,
    TargetKind,
    Transport,
)
from mcpscan.scanner import scan_target

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


ConsentCallback = Callable[[ConfiguredServer], bool]


async def scan_mcp_configs(
    config_path: Path | None = None,
    *,
    only: set[str] | None = None,
    consent: ConsentCallback | None = None,
    timeout_seconds: float = 90.0,
) -> ConfigScanResult:
    loaded = load_mcp_configs(config_path)
    selected = [server for server in loaded.servers if not only or server.name in only]
    skipped = list(loaded.skipped)
    skipped.extend(
        SkippedConfiguredServer(
            name=server.name,
            source_path=server.source_path,
            reason="filtered by --only",
            env_names=server.env_names,
        )
        for server in loaded.servers
        if only and server.name not in only
    )

    if not selected and not skipped:
        raise TargetError("No MCP servers selected for scanning.")

    server_results: list[ConfigServerResult] = []
    failures: list[ConfigServerFailure] = []
    for server in selected:
        if server.transport == Transport.STDIO and consent and not consent(server):
            skipped.append(
                SkippedConfiguredServer(
                    name=server.name,
                    source_path=server.source_path,
                    reason="no consent",
                    env_names=server.env_names,
                )
            )
            continue
        try:
            result = await scan_target(_target_for_server(server), timeout_seconds=timeout_seconds)
            server_results.append(
                ConfigServerResult(
                    name=server.name,
                    source_path=server.source_path,
                    transport=server.transport,
                    env_names=server.env_names,
                    result=result,
                )
            )
        except EnumerationError as exc:
            failures.append(
                ConfigServerFailure(
                    name=server.name,
                    source_path=server.source_path,
                    transport=server.transport,
                    error=str(exc),
                    env_names=server.env_names,
                )
            )

    findings_total = sum(len(server.result.findings) for server in server_results)
    summary = ConfigScanSummary(
        configs_found=len(loaded.paths),
        servers_total=len(loaded.servers) + len(loaded.skipped),
        servers_scanned=len(server_results),
        servers_failed=len(failures),
        servers_skipped=len(skipped),
        findings_total=findings_total,
        worst_grade=_worst_grade([server.result.grade for server in server_results]),
    )
    return ConfigScanResult(
        config_paths=loaded.paths,
        server_results=server_results,
        failures=failures,
        skipped=skipped,
        summary=summary,
    )


def _target_for_server(server: ConfiguredServer) -> ScanTarget:
    if server.transport == Transport.STDIO:
        return ScanTarget(
            raw=_redacted_command(server),
            kind=TargetKind.COMMAND,
            transport=Transport.STDIO,
            command=server.command,
            env=server.env,
        )
    return ScanTarget(
        raw=server.url,
        kind=TargetKind.URL,
        transport=Transport.HTTP,
        url=server.url,
        headers=server.headers,
    )


def _redacted_command(server: ConfiguredServer) -> str:
    command = " ".join(server.command or [])
    if server.env_names:
        env = " ".join(f"{name}=<redacted>" for name in server.env_names)
        return f"{env} {command}"
    return command


def _worst_grade(grades: list[str]) -> str:
    if not grades:
        return "A"
    return max(grades, key=lambda grade: GRADE_ORDER.get(grade, 0))
