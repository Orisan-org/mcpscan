from __future__ import annotations

import json

from mcpscan import __version__
from mcpscan.constants import SCANNER_NAME
from mcpscan.models import ScanResult


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
