from __future__ import annotations

import io

from rich.console import Console
from rich.table import Table

from mcpscan.models import ConfigScanResult, ScanResult


def render_terminal(result: ScanResult, *, no_color: bool = False) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, color_system=None if no_color else "auto", width=120)
    server = result.server.name or "unknown"
    version = f" v{result.server.version}" if result.server.version else ""
    console.print(f"Server: {server}{version}")
    console.print(f"Transport: {result.target.transport.value}")
    console.print(f"Grade: {result.grade}")
    table = Table("SEVERITY", "ID", "TARGET", "FINDING")
    for finding in result.findings:
        table.add_row(finding.severity.value.upper(), finding.id, finding.target, finding.evidence)
    if result.findings:
        console.print(table)
    else:
        console.print("No findings.")
    console.print(
        "Critical {critical}  High {high}  Medium {medium}  Low {low}  Info {info}".format(
            **result.counts
        )
    )
    for warning in result.warnings:
        console.print(f"Warning: {warning}")
    return buffer.getvalue()


def render_config_terminal(result: ConfigScanResult, *, no_color: bool = False) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, color_system=None if no_color else "auto", width=120)
    console.print("mcpscan config report")
    console.print(f"Configs found: {result.summary.configs_found}")
    console.print(
        f"Servers: {result.summary.servers_total} total, "
        f"{result.summary.servers_scanned} scanned, "
        f"{result.summary.servers_failed} failed, "
        f"{result.summary.servers_skipped} skipped"
    )
    console.print(f"Worst grade: {result.summary.worst_grade}")
    for server in result.server_results:
        console.print("")
        console.print(f"{server.name}")
        console.print(f"  Source: {server.source_path}")
        console.print(f"  Transport: {server.transport.value}")
        console.print(f"  Grade: {server.result.grade}")
        if server.env_names:
            console.print(f"  Env names observed: {len(server.env_names)}")
        if server.result.findings:
            table = Table("SEVERITY", "ID", "TARGET", "FINDING")
            for finding in server.result.findings:
                table.add_row(
                    finding.severity.value.upper(), finding.id, finding.target, finding.evidence
                )
            console.print(table)
        else:
            console.print("  No findings.")
    if result.failures:
        console.print("")
        console.print("Failures:")
        for failure in result.failures:
            console.print(f"  {failure.name}: {failure.error}")
    if result.skipped:
        console.print("")
        console.print("Skipped:")
        for skipped in result.skipped:
            console.print(f"  {skipped.name}: {skipped.reason}")
    console.print("")
    console.print("Privacy: payload_stored=false for all findings")
    return buffer.getvalue()
