from __future__ import annotations

import hashlib
import json
import uuid

from mcpscan import __version__
from mcpscan.models import ConfigScanResult, Finding, ScanResult
from mcpscan.scoring import effective_severity

SCHEMA_VERSION = "1.0.0"


def render_envelope(result: ScanResult) -> str:
    envelope = _base_envelope(
        run_id=_stable_uuid("run", _target_identifier(result), result.scan.timestamp_utc),
        timestamp=result.scan.timestamp_utc,
        target_type="mcp_server",
        target_identifier=_target_identifier(result),
    )
    envelope["findings"] = [_finding(finding, result) for finding in result.findings]
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def render_config_envelope(result: ConfigScanResult) -> str:
    timestamp = _config_timestamp(result)
    envelope = _base_envelope(
        run_id=_stable_uuid("config-run", "|".join(result.config_paths), timestamp),
        timestamp=timestamp,
        target_type="fleet",
        target_identifier=",".join(result.config_paths) or "mcp-config",
    )
    findings = []
    inventory = []
    coverage = []
    for server in result.server_results:
        item_id = _stable_id("inventory", server.source_path, server.name)
        inventory.append(
            {
                "id": item_id,
                "kind": "mcp_server",
                "name": server.name,
                "location": {"path": server.source_path},
                "capabilities": sorted(
                    {finding.capability.value for finding in server.result.findings}
                ),
                "coverage_status": "uncovered",
                "discovered_by": "mcpscan",
                "first_seen": server.result.scan.timestamp_utc,
                "last_seen": server.result.scan.timestamp_utc,
                "active": True,
            }
        )
        coverage.append(
            {
                "item_id": item_id,
                "discovered": True,
                "assessed": True,
                "enforced": False,
                "status": "partial",
                "gaps": ["Relay enforcement was not observed for this MCP server."],
            }
        )
        findings.extend(_finding(finding, server.result) for finding in server.result.findings)

    envelope["findings"] = findings
    envelope["inventory"] = inventory
    envelope["coverage"] = coverage
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def _base_envelope(
    *, run_id: str, timestamp: str, target_type: str, target_identifier: str
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "producer": {"tool": "mcpscan", "version": __version__},
        "run_id": run_id,
        "timestamp": timestamp,
        "target": {"type": target_type, "identifier": target_identifier},
    }


def _finding(finding: Finding, result: ScanResult) -> dict:
    return {
        "id": _stable_id("finding", finding.id, finding.target, finding.evidence),
        "rule_id": finding.id,
        "category": _category(finding),
        "severity": effective_severity(finding).value,
        "confidence": "high",
        "title": finding.title,
        "description": finding.evidence,
        "location": _location(finding),
        "evidence": {"redacted": True, "snippet": finding.evidence[:512] or "[redacted]"},
        "taxonomy": [{"framework": "owasp_mcp_top10", "id": finding.owasp_mcp}],
        "adjudication": finding.contextual_verdict.value,
        "recommendation": finding.remediation,
        "status": "open",
    }


def _location(finding: Finding) -> dict:
    if finding.capability.value in {
        "file_read",
        "file_write",
        "shell_exec",
        "code_eval",
        "credential_access",
        "data_exposure",
    }:
        return {"kind": "mcp_tool", "tool": finding.target}
    return {"kind": "mcp_resource", "resource": finding.target}


def _category(finding: Finding) -> str:
    if finding.capability.value in {"credential_access"}:
        return "secret"
    if finding.capability.value in {"data_exposure", "file_read"}:
        return "exposure"
    if finding.capability.value in {"prompt_anomaly"}:
        return "injection"
    if finding.capability.value in {"identity_spoof"}:
        return "supply_chain"
    if finding.capability.value in {"transport_security"}:
        return "misconfig"
    return "dangerous_capability"


def _target_identifier(result: ScanResult) -> str:
    return (
        result.target.url
        or result.target.raw
        or " ".join(result.target.command or [])
        or "mcp-target"
    )


def _config_timestamp(result: ConfigScanResult) -> str:
    timestamps = [server.result.scan.timestamp_utc for server in result.server_results]
    return max(timestamps) if timestamps else "1970-01-01T00:00:00+00:00"


def _stable_id(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join((kind, *parts)).encode("utf-8")).digest()
    prefix = "f" if kind == "finding" else "i"
    return f"{prefix}_{_base64url(digest)[:22]}"


def _stable_uuid(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))


def _base64url(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
