from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from mcpscan import __version__
from mcpscan.checks.registry import check_catalogue
from mcpscan.constants import EXIT_ENUMERATION, EXIT_FINDINGS, EXIT_INTERNAL, EXIT_OK, EXIT_USAGE
from mcpscan.errors import EnumerationError, McpScanError, TargetError
from mcpscan.models import Severity, Transport
from mcpscan.reporters.json_reporter import render_json
from mcpscan.reporters.markdown import render_markdown
from mcpscan.reporters.terminal import render_terminal
from mcpscan.scanner import scan_target
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
        str, typer.Option("--output", help="Report output: table, json, md.")
    ] = "table",
    out: Annotated[Path | None, typer.Option("--out", help="Write report to path.")] = None,
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
        result = asyncio.run(scan_target(scan_target_model, timeout_seconds=timeout))
        rendered = _render(result, output=output, no_color=no_color)
        if out:
            out.write_text(rendered, encoding="utf-8")
        else:
            typer.echo(rendered, nl=False)
        exit_code = EXIT_OK
        if any(severity_gte(finding.severity, severity_threshold) for finding in result.findings):
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


def _render(result, *, output: str, no_color: bool) -> str:
    if output == "table":
        return render_terminal(result, no_color=no_color)
    if output == "json":
        return render_json(result)
    if output == "md":
        return render_markdown(result)
    raise TargetError("--output must be one of: table, json, md.")
