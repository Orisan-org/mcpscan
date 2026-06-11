from __future__ import annotations

import json

from mcpscan import __version__
from mcpscan.constants import CHECKS_VERSION, NOT_CHECKED, REPORT_VERSION, SCANNER_NAME
from mcpscan.models import ConfigScanResult, ScanResult
from mcpscan.scoring import effective_severity


def recommendation_for(result: ScanResult) -> str:
    if result.counts.get("critical", 0):
        return "do_not_connect"
    if result.counts.get("high", 0):
        return "proceed_with_conditions"
    return "proceed"


def render_json(result: ScanResult) -> str:
    payload = {
        "report_version": REPORT_VERSION,
        "scan": {
            "mcpscan_version": __version__,
            "checks_version": CHECKS_VERSION,
            "timestamp_utc": result.scan.timestamp_utc,
            "target": _target_label(result),
            "transport": result.target.transport.value,
            "timeout_seconds": result.scan.timeout_seconds,
            "reproduce_command": result.scan.reproduce_command,
        },
        "server": {
            "name": result.server.name,
            "version": result.server.version,
            "transport": result.target.transport.value,
            "source": None,
        },
        "purpose_profile": result.purpose_profile.model_dump(mode="json"),
        "verdict_summary": {
            "recommendation": recommendation_for(result),
            "grade": result.grade,
            "counts_by_adjusted_severity": result.counts,
            "top_findings": _top_findings(result),
        },
        "surface": result.surface.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "not_checked": NOT_CHECKED,
        "warnings": result.warnings,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_config_json(result: ConfigScanResult) -> str:
    payload = {
        "scanner": {"name": SCANNER_NAME, "version": __version__},
        "report_version": REPORT_VERSION,
        "config": {
            "paths": result.config_paths,
            "configs_found": result.summary.configs_found,
            "servers_total": result.summary.servers_total,
            "servers_scanned": result.summary.servers_scanned,
            "servers_failed": result.summary.servers_failed,
            "servers_skipped": result.summary.servers_skipped,
        },
        "summary": {
            "findings_total": result.summary.findings_total,
            "worst_grade": result.summary.worst_grade,
        },
        "server_results": [
            {
                "name": server.name,
                "source_path": server.source_path,
                "transport": server.transport.value,
                "env": {"names": server.env_names, "count": len(server.env_names)},
                "server": server.result.server.model_dump(mode="json"),
                "summary": {
                    "grade": server.result.grade,
                    "counts": server.result.counts,
                },
                "purpose_profile": server.result.purpose_profile.model_dump(mode="json"),
                "surface": server.result.surface.model_dump(mode="json"),
                "findings": [finding.model_dump(mode="json") for finding in server.result.findings],
                "warnings": server.result.warnings,
            }
            for server in result.server_results
        ],
        "failures": [failure.model_dump(mode="json") for failure in result.failures],
        "skipped_servers": [skipped.model_dump(mode="json") for skipped in result.skipped],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _target_label(result: ScanResult) -> str:
    if result.target.url:
        return result.target.url
    if result.target.raw:
        return result.target.raw
    if result.target.command:
        return " ".join(result.target.command)
    return result.target.kind.value


def _top_findings(result: ScanResult) -> list[str]:
    lines: list[str] = []
    for finding in result.findings[:3]:
        severity = effective_severity(finding).value
        lines.append(f"{severity.upper()} {finding.id} on {finding.target}: {finding.evidence}")
    return lines
