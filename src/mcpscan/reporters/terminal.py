from __future__ import annotations

import io

from rich.console import Console
from rich.table import Table

from mcpscan.models import ScanResult


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
