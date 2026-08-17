from __future__ import annotations

import json

from mcpscan import __version__
from mcpscan.checks.registry import check_catalogue
from mcpscan.constants import SCANNER_NAME
from mcpscan.models import ConfigScanResult, Finding, ScanResult, Severity
from mcpscan.ruleset import RULESET_VERSION, ruleset_digest
from mcpscan.scoring import effective_severity
from mcpscan.tiers import TIER_DESCRIPTIONS


def render_sarif(result: ScanResult) -> str:
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [_run([(_artifact_uri(result), result)])],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_config_sarif(result: ConfigScanResult) -> str:
    """SARIF for the config path.

    `scan-config` had no SARIF output at all, which is the path CI actually
    uses. One run with every configured server's findings, each located by its
    config path so a reader can tell which entry produced what.
    """
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            _run(
                [
                    (server.source_path or server.name, server.result)
                    for server in result.server_results
                ]
            )
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _run(scans: list[tuple[str, ScanResult]]) -> dict:
    results = []
    notifications = []
    for uri, scan in scans:
        results.extend(_result(finding, uri) for finding in scan.findings)
        # A check that could not run is reported, not omitted. Without this a
        # SARIF consumer cannot tell "clean" from "not looked at" — the whole
        # point of the tier system, lost at the format boundary.
        for skipped in scan.checks_not_run:
            notifications.append(
                {
                    "level": "note",
                    "message": {
                        "text": (
                            f"{skipped['check_id']} ({skipped['title']}) did not run: {skipped['reason']}"
                        )
                    },
                    "descriptor": {"id": skipped["check_id"]},
                    "properties": {
                        "owasp_mcp": skipped["owasp_mcp"],
                        "evidence_tier": scan.tier.value,
                        "artifact": uri,
                        "outcome": "not_run",
                    },
                }
            )
    tiers = sorted({scan.tier.value for _, scan in scans})
    return {
        "tool": {
            "driver": {
                "name": SCANNER_NAME,
                "version": __version__,
                "informationUri": "https://github.com/Orisan-org/mcpscan",
                "rules": [_rule(entry) for entry in check_catalogue()],
                "properties": {
                    "ruleset_version": RULESET_VERSION,
                    "ruleset_digest": ruleset_digest(),
                },
            }
        },
        "invocation": {
            "executionSuccessful": True,
            "toolExecutionNotifications": notifications,
            "properties": {
                "evidence_tiers": tiers,
                "evidence_tier_descriptions": [TIER_DESCRIPTIONS[scan.tier] for _, scan in scans][
                    :1
                ],
                "checks_not_run_count": len(notifications),
            },
        },
        "results": results,
    }


def _rule(entry) -> dict:
    return {
        "id": entry.id,
        "name": entry.title,
        "shortDescription": {"text": entry.title},
        "fullDescription": {
            "text": f"{entry.title}. Capability: {entry.capability.value}. OWASP MCP: {entry.owasp_mcp}."
        },
        "helpUri": entry.reference,
        "properties": {
            "capability": entry.capability.value,
            "owasp_mcp": entry.owasp_mcp,
            "status": entry.status,
            "severity": entry.severity.value,
        },
    }


def _result(finding: Finding, artifact_uri: str) -> dict:
    return {
        "ruleId": finding.id,
        "level": _level(effective_severity(finding)),
        "message": {"text": finding.evidence},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    # No `snippet`. SARIF allows server-supplied text here, and
                    # populating it would put raw payload into a report whose
                    # every finding says payload_stored=false.
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": finding.target}],
            }
        ],
        "properties": {
            "capability": finding.capability.value,
            "owasp_mcp": finding.owasp_mcp,
            "scope": finding.scope.value,
            "contextual_verdict": finding.contextual_verdict.value,
            "original_severity": (finding.original_severity or finding.severity).value,
            "adjusted_severity": effective_severity(finding).value,
            "payload_stored": finding.payload_stored,
            "remediation": finding.remediation,
            "verdict_reasoning": finding.verdict_reasoning,
        },
    }


def _level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _artifact_uri(result: ScanResult) -> str:
    return result.target.url or result.target.raw or result.scan.reproduce_command or "mcp-target"
