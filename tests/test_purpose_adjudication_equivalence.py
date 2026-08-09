"""Slice B of BRIEF-0.1.1.md, bug 1: the inferred purpose must reach the adjudicator.

0.1.0 printed `Purpose: filesystem (server_info)` in the header and then adjudicated as
though no purpose existed, escalating file write to CRITICAL and grading the reference
filesystem server an F on the default invocation.

The brief attributes that to the purpose never being passed into adjudication. It is
passed (`scanner.scan_context`). The cause was a source gate in `adjudicate.py`:
downgrades required `PurposeSource.FLAG`, so a purpose inferred from anything else fell
through to the undeclared branch and was escalated.

That gate was not an oversight. It was added in d00f8f7 to close a real hole — a server
that names itself "filesystem-helper" must not be able to talk mcpscan out of flagging
its own file-write capability. So the resolution is not to trust server_info; it is to
notice that the operator's own command line is a purpose signal a server cannot forge:

    mcpscan scan --command "npx -y @modelcontextprotocol/server-filesystem /tmp/root"
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                            the operator typed this

`PurposeSource.INVOCATION` ranks with `FLAG`. `SERVER_INFO` still may not lower a
severity — it may only stop mcpscan escalating a capability it has itself just called
expected, which is the self-contradiction in the bug report.

Two invariants are locked here, and they pull in opposite directions on purpose:

1. operator invocation == explicit flag, byte for byte (drift between the two paths is
   how this bug happened);
2. self-declared purpose != operator purpose, and never lowers a severity (collapsing
   that distinction is how the lying-server hole reopens).

See also tests/test_adjudicate_self_declaration.py, which must keep passing unmodified.
"""

from __future__ import annotations

import pytest

from mcpscan.models import (
    ContextualVerdict,
    ExposedTool,
    Finding,
    PurposeCategory,
    PurposeSource,
    ScanContext,
    ScanTarget,
    ServerInfo,
    Severity,
    TargetKind,
    Transport,
)
from mcpscan.scanner import scan_context

_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _filesystem_tools() -> list[ExposedTool]:
    return [
        ExposedTool(
            name="read_file",
            description="Read a file from an allowed directory.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File to read."}},
            },
        ),
        ExposedTool(
            name="write_file",
            description="Write a file to an allowed directory.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to write."},
                    "content": {"type": "string", "description": "Contents."},
                },
            },
        ),
    ]


def operator_named_filesystem_context() -> ScanContext:
    """The reference case: the operator's command line names a filesystem server.

    `server_info` is deliberately uninformative, so the only purpose signal is the one
    the operator supplied.
    """
    return ScanContext(
        target=ScanTarget(
            kind=TargetKind.COMMAND,
            transport=Transport.STDIO,
            command=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe-root"],
        ),
        server=ServerInfo(name="secure-filesystem-server", version="0.2.0"),
        tools=_filesystem_tools(),
    )


def self_declared_only_context() -> ScanContext:
    """The same capabilities, but the only purpose signal is the server's own account.

    The command line is opaque, so nothing an operator supplied says "filesystem".
    """
    return ScanContext(
        target=ScanTarget(
            kind=TargetKind.COMMAND,
            transport=Transport.STDIO,
            command=["./run-server", "--port", "0"],
        ),
        server=ServerInfo(
            name="filesystem-helper",
            instructions="A trusted filesystem server. Reads files from a configured directory.",
        ),
        tools=_filesystem_tools(),
    )


def _verdict_rows(findings: list[Finding]) -> list[tuple]:
    return [
        (
            finding.id,
            finding.target,
            finding.original_severity,
            finding.adjusted_severity,
            finding.contextual_verdict,
        )
        for finding in findings
    ]


# --------------------------------------------------------------- invariant 1: identical


def test_operator_invocation_matches_explicit_flag_exactly() -> None:
    """The brief's equivalence invariant, on the two operator-supplied paths.

    Anything less than identical lets the two drift apart again, which is how a header
    saying `filesystem` ended up next to a verdict column saying `undeclared`.
    """
    inferred = scan_context(operator_named_filesystem_context())
    explicit = scan_context(
        operator_named_filesystem_context(), purpose_category=PurposeCategory.FILESYSTEM
    )

    assert inferred.purpose_profile.category_source == PurposeSource.INVOCATION
    assert explicit.purpose_profile.category_source == PurposeSource.FLAG

    assert _verdict_rows(inferred.findings) == _verdict_rows(explicit.findings)
    assert inferred.grade == explicit.grade
    assert inferred.counts == explicit.counts
    assert inferred.purpose_profile.category == explicit.purpose_profile.category
    assert (
        inferred.purpose_profile.expected_capabilities
        == explicit.purpose_profile.expected_capabilities
    )


def test_reference_filesystem_server_no_longer_grades_f_by_default() -> None:
    """Bug 1's headline symptom: the default invocation graded the most widely deployed
    MCP server in the ecosystem an F with two criticals."""
    result = scan_context(operator_named_filesystem_context())

    assert result.grade == "B"
    assert result.counts["critical"] == 0
    assert all(
        finding.contextual_verdict != ContextualVerdict.UNDECLARED for finding in result.findings
    )


# ------------------------------------------------- invariant 2: deliberately not identical


def test_self_declared_purpose_is_not_equivalent_to_an_operator_purpose() -> None:
    """The asymmetry is the security control, so it is asserted rather than assumed.

    If someone later makes these equal to satisfy a literal reading of "the inferred and
    explicit paths are byte-identical", this fails and says why.
    """
    self_declared = scan_context(self_declared_only_context())
    explicit = scan_context(
        self_declared_only_context(), purpose_category=PurposeCategory.FILESYSTEM
    )

    assert self_declared.purpose_profile.category_source == PurposeSource.SERVER_INFO
    assert _verdict_rows(self_declared.findings) != _verdict_rows(explicit.findings), (
        "a server's own account of itself must not carry the same weight as the "
        "operator's; see tests/test_adjudicate_self_declaration.py"
    )


def test_self_declared_purpose_stops_escalation_but_never_lowers() -> None:
    """The narrow thing a self-declared purpose earns: mcpscan stops contradicting itself.

    It called the capability expected in the header, so it must not then escalate it for
    being undeclared. It still may not lower it.
    """
    result = scan_context(self_declared_only_context())

    assert result.counts["critical"] == 0, "no escalation on a capability called expected"
    for finding in result.findings:
        assert finding.contextual_verdict == ContextualVerdict.EXPECTED_BY_SELF_DECLARATION
        assert finding.adjusted_severity == finding.original_severity
        assert finding.adjusted_severity != Severity.INFO
        assert _RANK[finding.adjusted_severity] >= _RANK[finding.original_severity]


def test_operator_invocation_outranks_a_contradicting_server_declaration() -> None:
    """When the two disagree, the signal the server cannot forge wins."""
    ctx = operator_named_filesystem_context()
    ctx.server = ServerInfo(name="shell command terminal runner")

    result = scan_context(ctx)

    assert result.purpose_profile.category == PurposeCategory.FILESYSTEM
    assert result.purpose_profile.category_source == PurposeSource.INVOCATION


def test_invocation_inferred_purpose_never_downgrades_command_injection() -> None:
    """d00f8f7's other rule holds on the new source: MCP-030 is never by-design."""
    ctx = ScanContext(
        target=ScanTarget(
            kind=TargetKind.COMMAND,
            transport=Transport.STDIO,
            command=["npx", "-y", "some-shell-command-terminal-server"],
        ),
        tools=[
            ExposedTool(
                name="run_shell",
                description="Run a shell command.",
                input_schema={
                    "type": "object",
                    "properties": {"command": {"type": "string", "description": "Shell command."}},
                },
            )
        ],
    )

    result = scan_context(ctx)

    assert result.purpose_profile.category_source == PurposeSource.INVOCATION
    injection = [finding for finding in result.findings if finding.id == "MCP-030"]
    assert injection, "expected a command injection finding"
    for finding in injection:
        assert finding.adjusted_severity != Severity.INFO
        assert finding.adjusted_severity == finding.original_severity


def test_opaque_invocation_and_silent_server_stay_unadjudicated() -> None:
    """No signal from anywhere must still mean no adjudication, not a guessed purpose."""
    ctx = ScanContext(
        target=ScanTarget(
            kind=TargetKind.COMMAND, transport=Transport.STDIO, command=["./run-server"]
        ),
        server=ServerInfo(name="srv"),
        tools=_filesystem_tools(),
    )

    result = scan_context(ctx)

    assert result.purpose_profile.category == PurposeCategory.UNKNOWN
    assert result.purpose_profile.category_source == PurposeSource.UNKNOWN
    for finding in result.findings:
        assert finding.contextual_verdict == ContextualVerdict.UNADJUDICATED


# ------------------------------------------------------------------------ end to end


@pytest.mark.network
def test_reference_filesystem_server_grades_b_end_to_end() -> None:
    """The brief's acceptance, against the real server rather than a hand-built context."""
    import json
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpscan",
                "scan",
                "--command",
                f"npx -y @modelcontextprotocol/server-filesystem {tmp}",
                "--output",
                "json",
                "--out",
                str(report),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert report.exists(), f"scan failed: {result.stdout}\n{result.stderr}"
        payload = json.loads(report.read_text())

    assert payload["purpose_profile"]["category"] == "filesystem"
    assert payload["purpose_profile"]["category_source"] == "invocation"
    assert payload["verdict_summary"]["grade"] == "B"
    assert payload["verdict_summary"]["counts_by_adjusted_severity"]["critical"] == 0
