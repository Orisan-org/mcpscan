from __future__ import annotations

import json

from mcpscan import __version__
from mcpscan.constants import SCANNER_NAME
from mcpscan.models import ConfigScanResult, ScanResult


def render_json(result: ScanResult) -> str:
    payload = {
        "scanner": {"name": SCANNER_NAME, "version": __version__},
        "target": {
            "transport": result.target.transport.value,
            "kind": result.target.kind.value,
            "url": result.target.url,
        },
        "server": result.server.model_dump(mode="json"),
        "summary": {"grade": result.grade, "counts": result.counts},
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "warnings": result.warnings,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_config_json(result: ConfigScanResult) -> str:
    payload = {
        "scanner": {"name": SCANNER_NAME, "version": __version__},
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
                "findings": [finding.model_dump(mode="json") for finding in server.result.findings],
                "warnings": server.result.warnings,
            }
            for server in result.server_results
        ],
        "failures": [failure.model_dump(mode="json") for failure in result.failures],
        "skipped_servers": [skipped.model_dump(mode="json") for skipped in result.skipped],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
