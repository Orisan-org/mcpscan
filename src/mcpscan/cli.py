from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from mcpscan import __version__
from mcpscan.checks.registry import check_catalogue
from mcpscan.config_scanner import scan_mcp_configs
from mcpscan.constants import EXIT_ENUMERATION, EXIT_FINDINGS, EXIT_INTERNAL, EXIT_OK, EXIT_USAGE
from mcpscan.errors import EnumerationError, McpScanError, TargetError
from mcpscan.models import ConfiguredServer, PurposeCategory, Severity, Transport
from mcpscan.reporters.envelope import render_config_envelope, render_envelope
from mcpscan.reporters.json_reporter import render_config_json, render_json
from mcpscan.reporters.markdown import render_config_markdown, render_markdown
from mcpscan.reporters.sarif import render_sarif
from mcpscan.reporters.terminal import render_config_terminal, render_terminal
from mcpscan.scanner import scan_target
from mcpscan.scoring import effective_severity
from mcpscan.target import resolve_target
from mcpscan.utils.severity import severity_gte

app = typer.Typer(no_args_is_help=True, help="Local-first security scanner for MCP servers.")
console = Console()


@app.callback(invoke_without_command=True)
def main(
    version_flag: Annotated[
        bool,
        typer.Option("--version", help="Show version and exit.", callback=None),
    ] = False,
) -> None:
    if version_flag:
        console.print(__version__)
        raise typer.Exit(EXIT_OK)


@app.command()
def version() -> None:
    console.print(__version__)


@app.command("list-checks")
def list_checks() -> None:
    table = Table("ID", "TITLE", "SEVERITY", "CAPABILITY", "OWASP", "STATUS")
    for entry in check_catalogue():
        table.add_row(
            entry.id,
            entry.title,
            entry.severity.value,
            entry.capability.value,
            entry.owasp_mcp,
            entry.status,
        )
    console.print(table)


@app.command()
def scan(
    target: Annotated[str | None, typer.Argument(help="Remote MCP URL target.")] = None,
    transport: Annotated[
        Transport | None, typer.Option("--transport", help="Transport type.")
    ] = None,
    command: Annotated[
        str | None, typer.Option("--command", help="Command for stdio MCP target.")
    ] = None,
    header: Annotated[
        list[str] | None, typer.Option("--header", help="Remote header 'Name: Value'.")
    ] = None,
    output: Annotated[
        str, typer.Option("--output", help="Report output: table, json, md, sarif.")
    ] = "table",
    out: Annotated[Path | None, typer.Option("--out", help="Write report to path.")] = None,
    envelope_out: Annotated[
        Path | None,
        typer.Option("--envelope-out", help="Write shared Orisan envelope JSON to path."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="Previous JSON report to compare for MCP-002 drift."),
    ] = None,
    purpose_category: Annotated[
        PurposeCategory | None,
        typer.Option(
            "--purpose-category",
            help="Declared purpose category for deterministic purpose profiling.",
        ),
    ] = None,
    purpose: Annotated[
        str | None,
        typer.Option("--purpose", help="Free-text declared purpose for deterministic profiling."),
    ] = None,
    severity_threshold: Annotated[
        Severity,
        typer.Option(
            "--severity-threshold", help="Exit 1 if any finding is at or above this severity."
        ),
    ] = Severity.HIGH,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help="Connection timeout in seconds. Cold-start npx/uvx servers may need 30+ seconds.",
        ),
    ] = 90.0,
    fail_on_warnings: Annotated[
        bool, typer.Option("--fail-on-warnings", help="Exit non-zero if warnings are present.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable terminal colors.")] = False,
) -> None:
    try:
        scan_target_model = resolve_target(
            target, command=command, transport=transport, headers=header
        )
        result = asyncio.run(
            scan_target(
                scan_target_model,
                timeout_seconds=timeout,
                baseline_path=baseline,
                purpose_category=purpose_category,
                purpose_text=purpose,
            )
        )
        rendered = _render(result, output=output, no_color=no_color)
        if out:
            out.write_text(rendered, encoding="utf-8")
        else:
            typer.echo(rendered, nl=False)
        if envelope_out:
            envelope_out.write_text(render_envelope(result), encoding="utf-8")
        exit_code = EXIT_OK
        if any(
            severity_gte(effective_severity(finding), severity_threshold)
            for finding in result.findings
        ):
            exit_code = EXIT_FINDINGS
        if fail_on_warnings and result.warnings and exit_code == EXIT_OK:
            exit_code = EXIT_FINDINGS
        raise typer.Exit(exit_code)
    except TargetError as exc:
        typer.echo(f"Input error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except EnumerationError as exc:
        typer.echo(f"Enumeration error: {exc}", err=True)
        raise typer.Exit(EXIT_ENUMERATION) from exc
    except McpScanError as exc:
        typer.echo(f"Scanner error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Internal scanner error: {exc}", err=True)
        raise typer.Exit(EXIT_INTERNAL) from exc


@app.command("scan-config")
def scan_config_command(
    config_path: Annotated[
        Path | None,
        typer.Argument(
            help="Optional explicit MCP config JSON file. If omitted, known config paths are discovered."
        ),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Execute configured stdio servers without prompting."),
    ] = False,
    only: Annotated[
        str | None,
        typer.Option("--only", help="Comma-separated server names to scan."),
    ] = None,
    output: Annotated[
        str, typer.Option("--output", help="Report output: table, terminal, json, md, markdown.")
    ] = "table",
    out: Annotated[Path | None, typer.Option("--out", help="Write report to path.")] = None,
    envelope_out: Annotated[
        Path | None,
        typer.Option("--envelope-out", help="Write shared Orisan envelope JSON to path."),
    ] = None,
    baseline_dir: Annotated[
        Path | None,
        typer.Option(
            "--baseline-dir",
            help="Directory for per-server baseline JSON reports used by MCP-002 drift detection.",
        ),
    ] = None,
    purpose_category: Annotated[
        PurposeCategory | None,
        typer.Option(
            "--purpose-category",
            help="Declared purpose category applied to scanned servers.",
        ),
    ] = None,
    purpose: Annotated[
        str | None,
        typer.Option("--purpose", help="Free-text declared purpose applied to scanned servers."),
    ] = None,
    severity_threshold: Annotated[
        Severity,
        typer.Option(
            "--severity-threshold", help="Exit 1 if any finding is at or above this severity."
        ),
    ] = Severity.HIGH,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help="Per-server connection timeout in seconds. Cold-start npx/uvx servers may need 30+ seconds.",
        ),
    ] = 90.0,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable terminal colors.")] = False,
) -> None:
    try:
        selected = _parse_only(only)
        consent = None if yes else _confirm_stdio_server
        result = asyncio.run(
            scan_mcp_configs(
                config_path,
                only=selected,
                consent=consent,
                timeout_seconds=timeout,
                baseline_dir=baseline_dir,
                purpose_category=purpose_category,
                purpose_text=purpose,
            )
        )
        rendered = _render_config(result, output=output, no_color=no_color)
        if out:
            out.write_text(rendered, encoding="utf-8")
        else:
            typer.echo(rendered, nl=False)
        if envelope_out:
            envelope_out.write_text(render_config_envelope(result), encoding="utf-8")

        if not result.server_results and result.failures:
            raise typer.Exit(EXIT_ENUMERATION)
        if any(
            severity_gte(effective_severity(finding), severity_threshold)
            for server in result.server_results
            for finding in server.result.findings
        ):
            raise typer.Exit(EXIT_FINDINGS)
        raise typer.Exit(EXIT_OK)
    except TargetError as exc:
        typer.echo(f"Input error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except McpScanError as exc:
        typer.echo(f"Scanner error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Internal scanner error: {exc}", err=True)
        raise typer.Exit(EXIT_INTERNAL) from exc


def _render(result, *, output: str, no_color: bool) -> str:
    if output == "table":
        return render_terminal(result, no_color=no_color)
    if output == "json":
        return render_json(result)
    if output == "md":
        return render_markdown(result)
    if output == "sarif":
        return render_sarif(result)
    raise TargetError("--output must be one of: table, json, md, sarif.")


def _render_config(result, *, output: str, no_color: bool) -> str:
    if output in {"table", "terminal"}:
        return render_config_terminal(result, no_color=no_color)
    if output == "json":
        return render_config_json(result)
    if output in {"md", "markdown"}:
        return render_config_markdown(result)
    raise TargetError("--output must be one of: table, terminal, json, md, markdown.")


def _parse_only(value: str | None) -> set[str] | None:
    if value is None:
        return None
    names = {item.strip() for item in value.split(",") if item.strip()}
    if not names:
        raise TargetError("--only must include at least one server name.")
    return names


def _confirm_stdio_server(server: ConfiguredServer) -> bool:
    console.print(f"Configured stdio MCP server {server.name!r} from {server.source_path}")
    if server.env_names:
        env = " ".join(f"{name}=<redacted>" for name in server.env_names)
        console.print(f"Env: {env}")
    console.print("Command:")
    console.print(f"  {' '.join(server.command or [])}")
    return typer.confirm("Execute and scan?", default=False)
