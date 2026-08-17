from __future__ import annotations

import asyncio
import json
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
from mcpscan.coverage import coverage_summary, render_coverage
from mcpscan.enumerator import enumerate_target
from mcpscan.errors import EnumerationError, McpScanError, TargetError
from mcpscan.models import ConfiguredServer, PurposeCategory, Severity, Transport
from mcpscan.orisan_format import render_document as render_orisan_document
from mcpscan.reporters.envelope import render_config_envelope, render_envelope
from mcpscan.reporters.json_reporter import render_config_json, render_json
from mcpscan.reporters.markdown import render_config_markdown, render_markdown
from mcpscan.reporters.sarif import render_config_sarif, render_sarif
from mcpscan.reporters.terminal import render_config_terminal, render_terminal
from mcpscan.ruleset import RULESET_VERSION, canonical_manifest_json, ruleset_digest
from mcpscan.scanner import config_context, scan_context, scan_target
from mcpscan.scoring import effective_severity
from mcpscan.sdk_compat import mcp_sdk_problem
from mcpscan.signing import (
    EXIT_CANNOT_VERIFY,
    SigningError,
    build_result_record,
    default_key_path,
    generate_key,
    load_private_key,
    public_key_pem,
    render_record,
    verify_record,
)
from mcpscan.snapshot import (
    PROFILE_FULL,
    PROFILE_HASHES,
    DriftMismatch,
    build_snapshot,
    compare_snapshots,
    load_snapshot,
    replay_context,
    replay_provenance,
    snapshot_body,
    write_snapshot,
)
from mcpscan.target import resolve_target
from mcpscan.utils.severity import severity_gte
from mcpscan.witness import WitnessError
from mcpscan.witness import read_config as read_witness_config
from mcpscan.witness import register as witness_register_log
from mcpscan.witness import submit as witness_submit

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


@app.command("snapshot")
def snapshot_command(
    target: Annotated[str | None, typer.Argument(help="Remote MCP URL target.")] = None,
    command: Annotated[
        str | None, typer.Option("--command", help="Command for stdio MCP target.")
    ] = None,
    transport: Annotated[
        Transport | None, typer.Option("--transport", help="Transport type.")
    ] = None,
    header: Annotated[
        list[str] | None, typer.Option("--header", help="Remote header 'Name: Value'.")
    ] = None,
    out: Annotated[Path, typer.Option("--out", help="Snapshot file to write.")] = Path(
        "mcpscan-snapshot.json"
    ),
    label: Annotated[
        str | None,
        typer.Option(
            "--label", help="Identity for this target; drift refuses to compare across labels."
        ),
    ] = None,
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="hashes (default, drift only) or full (retains tool text so the snapshot is replayable).",
        ),
    ] = PROFILE_HASHES,
    no_execute: Annotated[
        bool,
        typer.Option(
            "--no-execute", help="Record the launch surface only; do not start the server."
        ),
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Connection timeout in seconds.")
    ] = 90.0,
) -> None:
    """Record a server's surface so a later scan can tell what changed."""
    try:
        scan_target_model = resolve_target(
            target, command=command, transport=transport, headers=header
        )
        ctx = (
            config_context(scan_target_model)
            if no_execute
            else asyncio.run(enumerate_target(scan_target_model, timeout_seconds=timeout))
        )
        document = build_snapshot(ctx, label=label, profile=profile)
        write_snapshot(out, document)
        body = document["body"]
        surface = body["surface"]
        typer.echo(
            f"Snapshot written to {out} "
            f"({len(surface['tools'])} tool(s), tier {body['tier']}, profile {body['profile']}, "
            f"launch {' '.join(surface['launch']['argv_preview']) or surface['launch'].get('url') or 'n/a'})"
        )
        if body["profile"] != PROFILE_FULL:
            typer.echo(
                "  Hashes only: good for drift, not replayable. "
                "Use --profile full to make `scan --tier surface` possible."
            )
        raise typer.Exit(EXIT_OK)
    except TargetError as exc:
        typer.echo(f"Input error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except EnumerationError as exc:
        typer.echo(f"Enumeration error: {exc}", err=True)
        raise typer.Exit(EXIT_ENUMERATION) from exc


@app.command("drift")
def drift_command(
    baseline: Annotated[Path, typer.Option("--baseline", help="Snapshot to compare against.")],
    target: Annotated[str | None, typer.Argument(help="Remote MCP URL target.")] = None,
    command: Annotated[
        str | None, typer.Option("--command", help="Command for stdio MCP target.")
    ] = None,
    transport: Annotated[
        Transport | None, typer.Option("--transport", help="Transport type.")
    ] = None,
    header: Annotated[
        list[str] | None, typer.Option("--header", help="Remote header 'Name: Value'.")
    ] = None,
    against: Annotated[
        Path | None,
        typer.Option(
            "--against",
            help="Compare against a second snapshot instead of a live target. Executes nothing.",
        ),
    ] = None,
    no_execute: Annotated[
        bool,
        typer.Option(
            "--no-execute", help="Compare the launch surface only; do not start the server."
        ),
    ] = False,
    output: Annotated[str, typer.Option("--output", help="Report output: table, json.")] = "table",
    timeout: Annotated[
        float, typer.Option("--timeout", help="Connection timeout in seconds.")
    ] = 90.0,
) -> None:
    """Report what changed since a snapshot. Exit 0 no drift, 1 drift, 2 cannot compare."""
    try:
        base = load_snapshot(baseline)
        if against is not None:
            current = load_snapshot(against)
        else:
            scan_target_model = resolve_target(
                target, command=command, transport=transport, headers=header
            )
            ctx = (
                config_context(scan_target_model)
                if no_execute
                else asyncio.run(enumerate_target(scan_target_model, timeout_seconds=timeout))
            )
            current = build_snapshot(ctx, label=snapshot_body(base).get("label"))
        findings = compare_snapshots(base, current)

        if output == "json":
            typer.echo(
                json.dumps(
                    {
                        "baseline_label": snapshot_body(base).get("label"),
                        "baseline_captured_at": base["envelope"]["captured_at"],
                        "baseline_surface_version": snapshot_body(base).get("surface_version"),
                        "drift_detected": bool(findings),
                        "changes": [f.model_dump(mode="json") for f in findings],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        elif not findings:
            typer.echo(
                f"No drift against {baseline} "
                f"(label {snapshot_body(base).get('label')!r}, captured {base['envelope']['captured_at']})."
            )
        else:
            typer.echo(
                f"{len(findings)} change(s) against {baseline} (label {base.get('label')!r}):"
            )
            for finding in findings:
                typer.echo(f"  {finding.severity.value:<8} {finding.target:<12} {finding.evidence}")
        raise typer.Exit(EXIT_FINDINGS if findings else EXIT_OK)
    except DriftMismatch as exc:
        typer.echo(f"Cannot compare: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except TargetError as exc:
        typer.echo(f"Input error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except EnumerationError as exc:
        typer.echo(f"Enumeration error: {exc}", err=True)
        raise typer.Exit(EXIT_ENUMERATION) from exc


witness_app = typer.Typer(help="Optional: prove a signed verdict existed at a point in time.")
app.add_typer(witness_app, name="witness")


def _state_dir(override: Path | None) -> Path:
    return override or Path(os.environ.get("MCPSCAN_HOME", Path.home() / ".mcpscan"))


@witness_app.command("register")
def witness_register(
    url: Annotated[str, typer.Option("--url", help="Witness base URL.")],
    signing_key: Annotated[Path | None, typer.Option("--signing-key")] = None,
    state_dir: Annotated[Path | None, typer.Option("--state-dir")] = None,
) -> None:
    """Register with a witness and PIN the key it answers with."""
    try:
        key = load_private_key(signing_key or default_key_path())
        config = witness_register_log(_state_dir(state_dir), url, public_key_pem(key))
    except (SigningError, WitnessError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    typer.echo(f"Registered log {config['log_id']} with {config['url']}.")
    typer.echo("Witness key pinned. A different key later is an attack, not a rotation.")


@witness_app.command("status")
def witness_status(
    state_dir: Annotated[Path | None, typer.Option("--state-dir")] = None,
) -> None:
    """Show the pinned witness, if any."""
    config = read_witness_config(_state_dir(state_dir))
    if config is None:
        typer.echo("No witness registered. Scans run and results are marked unwitnessed.")
        raise typer.Exit(EXIT_OK)
    typer.echo(f"url        {config['url']}")
    typer.echo(f"log_id     {config['log_id']}")
    typer.echo(f"registered {config['registered_at']}")
    typer.echo(f"submitted  {config.get('next_index', 0)} result(s)")


@app.command("keygen")
def keygen_command(
    out: Annotated[
        Path | None, typer.Option("--out", help="Where to write the private key.")
    ] = None,
) -> None:
    """Create a signing key. Deliberate, never a side effect of a scan."""
    path = out or default_key_path()
    try:
        pem = generate_key(path)
    except SigningError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    typer.echo(f"Private key written to {path} (mode 600). Keep it; publish only the public key:\n")
    typer.echo(pem)


@app.command("verify-result")
def verify_result_command(
    record_path: Annotated[Path, typer.Argument(help="A signed scan result to check.")],
    pubkey: Annotated[
        Path | None, typer.Option("--pubkey", help="Pin the expected public key (PEM).")
    ] = None,
) -> None:
    """Check a signed result. Exit 0 verified, 1 tampered, 2 cannot verify."""
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"CANNOT VERIFY  {record_path} could not be read: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_VERIFY) from exc
    outcome = verify_record(
        record, expect_pubkey_pem=pubkey.read_text(encoding="utf-8") if pubkey else None
    )
    typer.echo(outcome.report(), nl=False)
    raise typer.Exit(outcome.exit_code)


@app.command("coverage")
def coverage_command(
    output: Annotated[str, typer.Option("--output", help="text or json.")] = "text",
) -> None:
    """What of the OWASP MCP Top 10 has a check, and what each check inspects."""
    summary = coverage_summary()
    if output == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
        return
    if output != "text":
        typer.echo("--output must be text or json.", err=True)
        raise typer.Exit(EXIT_USAGE)
    typer.echo(render_coverage(summary), nl=False)


@app.command("ruleset")
def ruleset_command(
    manifest: Annotated[
        bool,
        typer.Option(
            "--manifest", help="Print the full canonical manifest the digest is taken over."
        ),
    ] = False,
) -> None:
    """Show the ruleset version and digest, or the manifest behind it."""
    if manifest:
        typer.echo(canonical_manifest_json())
        return
    typer.echo(f"ruleset_version {RULESET_VERSION}")
    typer.echo(f"ruleset_digest  {ruleset_digest()}")


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
        str,
        typer.Option("--output", help="Report output: table, json, md, sarif, orisan."),
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
    no_execute: Annotated[
        bool,
        typer.Option(
            "--no-execute",
            help="Never start or contact the server. Config-tier checks only; the rest are reported as not run.",
        ),
    ] = False,
    sign_result: Annotated[
        Path | None,
        typer.Option("--sign-result", help="Write a signed result record to this path."),
    ] = None,
    signing_key: Annotated[
        Path | None, typer.Option("--signing-key", help="Private key to sign with.")
    ] = None,
    witness: Annotated[
        bool,
        typer.Option(
            "--witness",
            help="Submit the signed verdict digest to the registered witness. Never blocks the scan.",
        ),
    ] = False,
    witness_state_dir: Annotated[Path | None, typer.Option("--state-dir")] = None,
    from_snapshot: Annotated[
        Path | None,
        typer.Option(
            "--from-snapshot",
            help="Replay a `--profile full` snapshot. Runs every check with zero execution.",
        ),
    ] = None,
    tier: Annotated[
        str | None,
        typer.Option("--tier", help="config, surface or live. surface requires --from-snapshot."),
    ] = None,
    fail_on_warnings: Annotated[
        bool, typer.Option("--fail-on-warnings", help="Exit non-zero if warnings are present.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable terminal colors.")] = False,
) -> None:
    try:
        if tier is not None and tier not in {"config", "surface", "live"}:
            raise TargetError("--tier must be one of: config, surface, live.")
        if tier == "surface" and from_snapshot is None:
            raise TargetError(
                "--tier surface replays a stored snapshot, so it needs --from-snapshot <file>. "
                "Capture one with `mcpscan snapshot --profile full`."
            )
        if from_snapshot is not None and tier == "live":
            raise TargetError("--tier live contradicts --from-snapshot; a replay starts nothing.")

        if from_snapshot is not None:
            document = load_snapshot(from_snapshot)
            ctx = replay_context(document, from_snapshot)
            result = scan_context(
                ctx,
                baseline_path=baseline,
                purpose_category=purpose_category,
                purpose_text=purpose,
                replayed_from=replay_provenance(document, from_snapshot),
            )
        else:
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
                    execute=not (no_execute or tier == "config"),
                )
            )
        rendered = _render(result, output=output, no_color=no_color)
        if out:
            out.write_text(rendered, encoding="utf-8")
        else:
            typer.echo(rendered, nl=False)
        if sign_result:
            key_path = signing_key or default_key_path()
            key = None
            if key_path.exists():
                key = load_private_key(key_path)
            record = build_result_record(result, key=key)
            sign_result.write_text(render_record(record), encoding="utf-8")
            if witness and key is not None:
                outcome = witness_submit(
                    _state_dir(witness_state_dir), record["body_sha256"], key.sign
                )
                record["witness"] = (
                    {
                        "log_id": read_witness_config(_state_dir(witness_state_dir))["log_id"],
                        "index": outcome.index,
                        "witnessed_at": outcome.receipt.get("witnessed_at")
                        if outcome.receipt
                        else None,
                    }
                    if outcome.ok
                    else {"submitted": False, "reason": outcome.error}
                )
                sign_result.write_text(render_record(record), encoding="utf-8")
                if outcome.ok:
                    typer.echo(f"Witnessed at index {outcome.index}.")
                else:
                    # Never fatal. The scan and its signature stand alone.
                    typer.echo(f"Not witnessed: {outcome.error}", err=True)
            elif witness:
                typer.echo(
                    "Not witnessed: no signing key, so there is no verdict to submit.", err=True
                )

            if key is None:
                # Stated, not silent. An unsigned record is not a signed one.
                typer.echo(
                    f"Result written UNSIGNED to {sign_result}: no key at {key_path}. "
                    "Create one with `mcpscan keygen`.",
                    err=True,
                )
            else:
                typer.echo(
                    f"Signed result written to {sign_result} (body {record['body_sha256'][:16]}…)"
                )

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
        str,
        typer.Option("--output", help="Report output: table, terminal, json, md, markdown, sarif."),
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
    no_execute: Annotated[
        bool,
        typer.Option(
            "--no-execute",
            help="Never start or contact any configured server. Config-tier checks only.",
        ),
    ] = False,
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
                execute=not no_execute,
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
    if output == "orisan":
        return render_orisan_document(result)
    raise TargetError("--output must be one of: table, json, md, sarif, orisan.")


def _render_config(result, *, output: str, no_color: bool) -> str:
    if output in {"table", "terminal"}:
        return render_config_terminal(result, no_color=no_color)
    if output == "json":
        return render_config_json(result)
    if output in {"md", "markdown"}:
        return render_config_markdown(result)
    if output == "sarif":
        return render_config_sarif(result)
    raise TargetError("--output must be one of: table, terminal, json, md, markdown, sarif.")


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
