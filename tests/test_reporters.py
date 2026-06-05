import json

from mcpscan.reporters.json_reporter import render_json
from mcpscan.reporters.markdown import render_markdown
from mcpscan.reporters.terminal import render_terminal
from mcpscan.scanner import scan_context
from tests.helpers import malicious_context


def test_json_contains_payload_stored_false() -> None:
    payload = json.loads(render_json(scan_context(malicious_context())))

    assert payload["findings"]
    assert all(finding["payload_stored"] is False for finding in payload["findings"])


def test_markdown_includes_remediation() -> None:
    report = render_markdown(scan_context(malicious_context()))

    assert "Remediation:" in report


def test_terminal_does_not_crash() -> None:
    report = render_terminal(scan_context(malicious_context()), no_color=True)

    assert "Grade:" in report
