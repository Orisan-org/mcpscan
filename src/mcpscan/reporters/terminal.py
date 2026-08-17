from __future__ import annotations

import io

from rich.console import Console
from rich.table import Table

from mcpscan.models import ConfigScanResult, ScanResult
from mcpscan.ruleset import RULESET_VERSION, ruleset_digest
from mcpscan.scoring import effective_severity
from mcpscan.tiers import TIER_DESCRIPTIONS, grade_label


def render_terminal(result: ScanResult, *, no_color: bool = False) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, color_system=None if no_color else "auto", width=120)
    server = result.server.name or "unknown"
    version = f" v{result.server.version}" if result.server.version else ""
    console.print(f"Server: {server}{version}")
    console.print(f"Transport: {result.target.transport.value}")
    console.print(
        f"Purpose: {result.purpose_profile.category.value} "
        f"({result.purpose_profile.category_source.value})"
    )
    # Parentheses, not brackets: Rich reads [..] as console markup and silently
    # swallowed the whole annotation, leaving a bare "Grade: A" behind.
    console.print(f"Grade: {grade_label(result.grade, result.tier, result.checks_not_run)}")
    console.print(f"Evidence: {TIER_DESCRIPTIONS[result.tier]}")
    console.print(f"Ruleset: v{RULESET_VERSION} digest {ruleset_digest()[:16]}")
    if result.replayed_from:
        # Loud, and above the findings. A replay describes the world as it was
        # when the snapshot was taken, not as it is now.
        provenance = result.replayed_from
        console.print(
            f"Replayed from: {provenance.get('snapshot_path')}\n"
            f"  captured {provenance.get('captured_at')} "
            f"({provenance.get('age_human', 'unknown age')} ago) — "
            "findings describe the surface AS CAPTURED, not as it is now"
        )
    table = Table("SEVERITY", "VERDICT", "ID", "TARGET", "FINDING")
    for finding in result.findings:
        table.add_row(
            _severity_label(finding),
            finding.contextual_verdict.value,
            finding.id,
            finding.target,
            finding.evidence,
        )
    if result.findings:
        console.print(table)
    else:
        console.print("No findings.")
    if result.checks_not_run:
        # Not a finding, and not silence. A check that could not run is the one
        # thing a reader must not mistake for a check that passed.
        console.print(f"\nNot checked at this tier ({len(result.checks_not_run)}):")
        for item in result.checks_not_run:
            console.print(f"  {item['check_id']}  {item['title']} — {item['reason']}")
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
    console.print(f"Worst grade: {_worst_grade_label(result.summary.worst_grade)}")
    for server in result.server_results:
        console.print("")
        console.print(f"{server.name}")
        console.print(f"  Source: {server.source_path}")
        console.print(f"  Transport: {server.transport.value}")
        console.print(
            f"  Purpose: {server.result.purpose_profile.category.value} "
            f"({server.result.purpose_profile.category_source.value})"
        )
        console.print(f"  Grade: {server.result.grade}")
        if server.env_names:
            console.print(f"  Env names observed: {len(server.env_names)}")
        if server.result.findings:
            table = Table("SEVERITY", "VERDICT", "ID", "TARGET", "FINDING")
            for finding in server.result.findings:
                table.add_row(
                    _severity_label(finding),
                    finding.contextual_verdict.value,
                    finding.id,
                    finding.target,
                    finding.evidence,
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


def _severity_label(finding) -> str:
    adjusted = effective_severity(finding)
    if adjusted == finding.severity:
        return adjusted.value.upper()
    return f"{adjusted.value.upper()} (was {finding.severity.value.upper()})"


def _worst_grade_label(worst_grade: str | None) -> str:
    """Never render a grade for an empty result set. See BRIEF-0.1.1.md bug 2b."""
    return worst_grade if worst_grade else "not assessed (no server was scanned)"
