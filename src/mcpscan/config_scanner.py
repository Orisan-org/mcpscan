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
    PurposeCategory,
    ScanTarget,
    SkippedConfiguredServer,
    TargetKind,
    TargetOrigin,
    Transport,
)
from mcpscan.reporters.json_reporter import render_json
from mcpscan.scanner import scan_target

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


ConsentCallback = Callable[[ConfiguredServer], bool]


async def scan_mcp_configs(
    config_path: Path | None = None,
    *,
    only: set[str] | None = None,
    consent: ConsentCallback | None = None,
    timeout_seconds: float = 90.0,
    baseline_dir: Path | None = None,
    purpose_category: PurposeCategory | None = None,
    purpose_text: str | None = None,
    execute: bool = True,
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
    if baseline_dir:
        baseline_dir.mkdir(parents=True, exist_ok=True)
    for server in selected:
        # With execution off there is nothing to consent to: nothing is
        # started and nothing is contacted, so the prompt is skipped entirely
        # rather than asked and ignored.
        if execute and server.transport == Transport.STDIO and consent and not consent(server):
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
            baseline_path = _baseline_path(baseline_dir, server.name)
            result = await scan_target(
                _target_for_server(server),
                timeout_seconds=timeout_seconds,
                execute=execute,
                baseline_path=baseline_path if baseline_path and baseline_path.exists() else None,
                purpose_category=purpose_category,
                purpose_text=purpose_text,
            )
            if baseline_path:
                baseline_path.write_text(render_json(result), encoding="utf-8")
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
    """Build a scan target from a config entry.

    ``origin=CONFIG`` is load-bearing, not bookkeeping. It is what stops a command line
    read out of a config file from being treated as operator intent and downgrading a
    finding: the snippet may have been copy-pasted from the server's own install docs.
    See the trust invariant in adjudicate.py.
    """
    if server.transport == Transport.STDIO:
        return ScanTarget(
            raw=_redacted_command(server),
            kind=TargetKind.COMMAND,
            transport=Transport.STDIO,
            origin=TargetOrigin.CONFIG,
            command=server.command,
            env=server.env,
        )
    return ScanTarget(
        raw=server.url,
        kind=TargetKind.URL,
        transport=Transport.HTTP,
        origin=TargetOrigin.CONFIG,
        url=server.url,
        headers=server.headers,
    )


def _redacted_command(server: ConfiguredServer) -> str:
    command = " ".join(server.command or [])
    if server.env_names:
        env = " ".join(f"{name}=<redacted>" for name in server.env_names)
        return f"{env} {command}"
    return command


def _worst_grade(grades: list[str]) -> str | None:
    """The worst grade across scanned servers, or None if nothing was scanned.

    0.1.0 returned "A" for an empty list, so a run that scanned nothing and failed
    everything still reported `Worst grade: A`. That is a claim that servers were
    assessed and found clean, which is not true. See BRIEF-0.1.1.md bug 2b.
    """
    if not grades:
        return None
    return max(grades, key=lambda grade: GRADE_ORDER.get(grade, 0))


def _baseline_path(baseline_dir: Path | None, server_name: str) -> Path | None:
    if baseline_dir is None:
        return None
    safe_name = "".join(
        char if char.isalnum() or char in {"-", "_"} else "_" for char in server_name
    )
    return baseline_dir / f"{safe_name}.json"
