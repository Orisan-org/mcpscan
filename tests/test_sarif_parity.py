"""SARIF must carry exactly the same findings as the default report.

Same count, no suppression, no additions. render_sarif maps result.findings 1:1,
so this guards against a future reporter change that silently drops or adds a
finding relative to the canonical list and the severity counts.
"""

import json

from mcpscan.reporters.sarif import render_sarif
from mcpscan.scanner import scan_context
from tests.helpers import malicious_context


def test_sarif_finding_count_matches_report_no_suppression_no_additions():
    result = scan_context(malicious_context())
    sarif = json.loads(render_sarif(result))
    sarif_results = sarif["runs"][0]["results"]

    # Same count as the canonical finding list...
    assert len(sarif_results) == len(result.findings)
    # ...the severity counts do not suppress any finding...
    assert sum(result.counts.values()) == len(result.findings)
    # ...and the exact finding ids match (no additions, no drops).
    assert sorted(r["ruleId"] for r in sarif_results) == sorted(f.id for f in result.findings)
