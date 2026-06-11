from __future__ import annotations

import json

from mcpscan import __version__
from mcpscan.checks.registry import check_catalogue
from mcpscan.constants import SCANNER_NAME
from mcpscan.models import Finding, ScanResult, Severity
from mcpscan.scoring import effective_severity


def render_sarif(result: ScanResult) -> str:
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": SCANNER_NAME,
                        "version": __version__,
                        "informationUri": "https://github.com/Orisan-org/mcpscan",
                        "rules": [_rule(entry) for entry in check_catalogue()],
                    }
                },
                "results": [_result(finding, result) for finding in result.findings],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


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


def _result(finding: Finding, scan_result: ScanResult) -> dict:
    return {
        "ruleId": finding.id,
        "level": _level(effective_severity(finding)),
        "message": {"text": finding.evidence},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(scan_result)},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": finding.target}],
            }
        ],
        "properties": {
            "capability": finding.capability.value,
            "owasp_mcp": finding.owasp_mcp,
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
