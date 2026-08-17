from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from mcpscan import __version__
from mcpscan.capabilities import owasp_coverage
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
from mcpscan.sdk_compat import mcp_sdk_problem
from mcpscan.target import resolve_target
from mcpscan.utils.severity import severity_gte

app = typer.Typer(no_args_is_help=True, help="Local-first security scanner for MCP servers.")
console = Console()

#: Commands that talk to an MCP server, and so depend on the mcp SDK behaving as built.
_SDK_DEPENDENT_COMMANDS = {"scan", "scan-config"}


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version_flag: Annotated[
        bool,
        typer.Option("--version", help="Show version and exit.", callback=None),
    ] = False,
) -> None:
    if version_flag:
        console.print(__version__)
        raise typer.Exit(EXIT_OK)

    # Fail before scanning, not partway through it. An mcp SDK outside the supported
    # range does not degrade gracefully: it produces a scan that silently omits a
    # transport. See BRIEF-0.1.1.md bug 3. `version` and `list-checks` stay usable on a
    # broken install so the environment can still be reported.
    if ctx.invoked_subcommand in _SDK_DEPENDENT_COMMANDS:
        problem = mcp_sdk_problem()
        if problem is not None:
            typer.echo(f"Incompatible mcp SDK: {problem}", err=True)
            raise typer.Exit(EXIT_INTERNAL)


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

    # Printed with the catalogue, not buried in the README. A reader deciding
    # whether this tool covers their threat model needs the gaps in the same
    # view as the coverage.
    coverage = owasp_coverage()
    uncovered = {k: v for k, v in coverage.items() if v["status"] == "no_check_implemented"}
    console.print(
        f"\nOWASP MCP Top 10: {len(coverage) - len(uncovered)} of {len(coverage)} categories have a check."
    )
    for category, entry in uncovered.items():
        console.print(f"  {category}  {entry['title']}  — {entry['detail']}")


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
    push_envelope: Annotated[
        bool,
        typer.Option(
            "--push-envelope", help="POST the shared Orisan envelope to the control plane."
        ),
    ] = False,
    control_plane_url: Annotated[
        str,
        typer.Option("--control-plane-url", help="Control-plane base URL."),
    ] = os.environ.get("ORISAN_CONTROL_PLANE_URL", "http://127.0.0.1:8787"),
    ingest_token: Annotated[
        str | None,
        typer.Option("--ingest-token", help="Control-plane ingest bearer token."),
    ] = os.environ.get("ORISAN_INGEST_TOKEN"),
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
            envelope_payload = render_envelope(result)
            envelope_out.write_text(envelope_payload, encoding="utf-8")
        elif push_envelope:
            envelope_payload = render_envelope(result)
        else:
            envelope_payload = None
        if push_envelope and envelope_payload is not None:
            run_id = _push_envelope(envelope_payload, control_plane_url, ingest_token)
            if not out and not rendered.endswith("\n"):
                typer.echo()
            typer.echo(
                f"Envelope pushed: {control_plane_url.rstrip('/')}/v1/envelopes run_id={run_id}"
            )
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
    push_envelope: Annotated[
        bool,
        typer.Option(
            "--push-envelope", help="POST the shared Orisan envelope to the control plane."
        ),
    ] = False,
    control_plane_url: Annotated[
        str,
        typer.Option("--control-plane-url", help="Control-plane base URL."),
    ] = os.environ.get("ORISAN_CONTROL_PLANE_URL", "http://127.0.0.1:8787"),
    ingest_token: Annotated[
        str | None,
        typer.Option("--ingest-token", help="Control-plane ingest bearer token."),
    ] = os.environ.get("ORISAN_INGEST_TOKEN"),
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
            envelope_payload = render_config_envelope(result)
            envelope_out.write_text(envelope_payload, encoding="utf-8")
        elif push_envelope:
            envelope_payload = render_config_envelope(result)
        else:
            envelope_payload = None
        if push_envelope and envelope_payload is not None:
            run_id = _push_envelope(envelope_payload, control_plane_url, ingest_token)
            if not out and not rendered.endswith("\n"):
                typer.echo()
            typer.echo(
                f"Envelope pushed: {control_plane_url.rstrip('/')}/v1/envelopes run_id={run_id}"
            )

        # Nothing was assessed, so there is no clean result to report. Exit 0 on an
        # empty run is the machine-readable form of the same false clean bill of health
        # that bug 2b is about: a CI pipeline reads it as "these configs are fine".
        # Failures are an enumeration problem; an all-skipped run is the operator's
        # choices (declined consent, or an --only filter that matched nothing).
        if not result.server_results:
            raise typer.Exit(EXIT_ENUMERATION if result.failures else EXIT_USAGE)
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


def _push_envelope(envelope_payload: str, control_plane_url: str, ingest_token: str | None) -> str:
    endpoint = f"{control_plane_url.rstrip('/')}/v1/envelopes"
    headers = {"content-type": "application/json"}
    if ingest_token:
        headers["authorization"] = f"Bearer {ingest_token}"
    try:
        response = httpx.post(endpoint, content=envelope_payload, headers=headers, timeout=10.0)
    except httpx.HTTPError as exc:
        raise McpScanError(f"Failed to push envelope to control plane: {exc}") from exc
    if response.status_code < 200 or response.status_code > 299:
        raise McpScanError(
            f"Control plane rejected envelope: HTTP {response.status_code}: {response.text[:500]}"
        )
    try:
        body = response.json()
    except ValueError:
        return "unknown"
    run = body.get("run") if isinstance(body, dict) else None
    run_id = run.get("run_id") if isinstance(run, dict) else None
    return str(run_id or "unknown")


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
