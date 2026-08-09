# Changelog

## 0.1.1 - 2026-08-09

Correctness and honesty release. Remote scanning worked again from a fresh install,
the adjudicator stopped contradicting its own header, and two entries in the build
brief were corrected rather than implemented. Green against the dependency set pinned
in this release (`mcp[cli]>=1.0.0,<2`); the `wheel-canary` workflow re-verifies that
weekly against a fresh resolution.

### Added

- Added `PurposeSource.INVOCATION`: purpose inferred from the stdio command line or
  remote URL typed at the CLI. It ranks with `--purpose`, because the operator wrote it
  and a server cannot forge it.
- Added `PurposeSource.CONFIG`: the same inference when the target came from an MCP
  client config file. Reported separately and may not downgrade — install snippets are
  copy-pasted from server-authored docs, so the string can be the server talking.
- Added the `expected_unconfirmed` contextual verdict, for a capability matching a
  purpose mcpscan inferred but the operator did not confirm. Severity is left exactly
  where the check set it — not escalated, and not lowered.
- Documented the adjudication trust invariant in `adjudicate.py`, the README and
  `docs/PURPOSE_TAXONOMY.md`: any purpose source may escalate a severity, only an
  operator-supplied one may downgrade it.
- Added a wheel test harness (`tests/test_wheel_install.py`, `pytest -m wheel`) that
  builds the wheel, installs it into a clean unconstrained virtualenv, and runs the
  headline commands from the installed console script against real fixture servers.
  Every other test runs against the repo tree, which is why bug 3 shipped unseen.
- Added an mcp SDK version guard (`src/mcpscan/sdk_compat.py`). When the dependency
  pin is bypassed, `scan` and `scan-config` refuse and name the installed version
  instead of producing a scan that silently omits a transport. `version` and
  `list-checks` still work, so a broken environment can be reported.
- Added a weekly wheel canary (`.github/workflows/wheel-canary.yml`) that re-runs the
  wheel harness against a fresh, uncached dependency resolution and files an issue when
  it breaks. Push-triggered CI cannot catch a break caused by the calendar rather than
  by a commit.

### Changed

- `scan-config` now exits non-zero when zero servers were scanned, including when every
  server was skipped by declined consent or an `--only` filter that matched nothing.
  Exit 0 on an empty run is the machine-readable form of a false clean bill of health.
  Failures exit `3`; an all-skipped run exits `2`.
- The environment a stdio server is launched with is now computed by mcpscan
  (`connectors/stdio.child_environment`) instead of being left to the mcp SDK's default:
  the SDK's safe allowlist, with config values overlaid on top, and the rest of
  `os.environ` withheld from a process mcpscan runs because it may be hostile. No
  behaviour change today; it stops the child environment being a property of whichever
  SDK is resolved.

### Fixed

- Fixed stdio connector failures collapsing three different problems into
  `Connection closed`. The message now names the stage — `spawn` (the command never
  started), `handshake` (the process started and exited), `handshake` (the process
  started and was still working at the timeout) — and echoes the failing command. A
  process that starts and then fails to speak MCP is no longer reported as having
  failed to start.
- Fixed `Worst grade: A` being reported when zero servers were scanned. `worst_grade` is
  now `None` in JSON and renders as "not assessed (no server was scanned)". A grade over
  an empty result set asserts that something was assessed and found clean.
- Fixed the adjudicator ignoring a purpose it had already resolved and printed. A scan
  of the reference filesystem server showed `Purpose: filesystem (server_info)` in the
  header and then graded it `F`, escalating file write to `CRITICAL` for being
  "undeclared". Downgrades required `PurposeSource.FLAG`, so any other source fell
  through to the undeclared branch. The default invocation now grades that server `B`,
  identically to `--purpose-category filesystem`. Self-declared purpose still cannot
  lower a severity.
- Fixed remote scanning being dead on every fresh install. The distribution declared
  `mcp[cli]>=1.0.0` with no upper bound; PyPI resolved that to mcp 2.0.0, which renamed
  `streamablehttp_client` and removed `mcp.server.fastmcp` with no aliases. Now pinned
  to `mcp[cli]>=1.0.0,<2`. Adapting to the mcp 2.0 API is tracked separately.
- Fixed transport import failures reporting as "`<transport>` is not available in the
  installed mcp SDK", wording that read as a capability gap rather than a broken
  install. The message now names the installed version and the supported range.

## 0.1.0 - 2026-07-23

First public release, published to PyPI as `orisan-mcpscan` (the distribution name
`mcpscan` is blocked by PyPI's name-similarity guard; the import package and CLI
command remain `mcpscan`). Full test suite green on Python 3.11-3.14 **against the
dependency set resolved on 2026-07-23** (mcp 1.x); 0.1.0 declared `mcp[cli]>=1.0.0`
with no upper bound, and was not green against later resolutions. All entries below
shipped in 0.1.0.

### Added

- Added the approved build plan to `docs/BUILD_PLAN.md`.
- Added stdio integration tests for benign, malicious, slow-start, timeout, and malformed subprocess behavior.
- Added a network-marked stdio test for the reference filesystem server.
- Added machine-readable check/finding metadata for capability class and OWASP MCP Top 10 mapping.
- Added `mcpscan scan-config` for MCP client config files, including known config discovery, stdio consent prompts, remote URL entries, env redaction, and aggregate reports.
- Added hash-only surface snapshots to JSON reports.
- Added MCP-002 tool definition drift detection with `mcpscan scan --baseline`.
- Added `scan-config --baseline-dir` for per-server baseline files.
- Added deterministic purpose profiles and a documented static purpose taxonomy.
- Added deterministic contextual verdicts with adjusted severity.
- Added SARIF 2.1.0 output for single-target scans.
- Added corpus ground-truth label schema validation and scoring tooling.
- Added provisional corpus score outputs and an unmapped findings review queue.
- Added exact toy corpus metric tests using hand-computed expected values.
- Added a benchmark method skeleton for label freeze, review, disputes, and reproduction.

### Changed

- Increased the CLI default connection timeout from 20 seconds to 90 seconds for cold-start stdio servers.
- Expanded `mcpscan list-checks`, JSON reports, and Markdown reports with capability and OWASP MCP metadata.
- Changed MCP-002 from deferred to active when a baseline report is supplied.
- Changed single-target JSON reports to report version `2.0` with scan metadata, verdict summary, not-checked statements, and schema validation.

### Fixed

- Applied stdio `--timeout` to the actual MCP handshake/enumeration path.
- Unwrapped nested `ExceptionGroup`/TaskGroup failures so user-facing enumeration errors show the real innermost cause.

## v0.1.0-alpha.2 - 2026-06-06

Validation-driven alpha patch.

### Fixed

- Reduced MCP-030 false positives by requiring actual command/code execution semantics.
- Fixed MCP-010 false negative for fetch-style outbound network capability by detecting URL/URI-like inputs on fetch/browser/request/download/crawl/scrape tools.
- Improved CLI ergonomics for unsupported local config/path targets.
- Rejected `--header` with stdio commands instead of silently ignoring it.
- Improved dead remote URL connection/refused errors so they do not collapse to generic TaskGroup wording.

### Added

- Validation notes for memory, filesystem, and fetch MCP server testing.
- Stale/global install troubleshooting documentation for validation workflows.

### Deferred

- MCP-002 baseline/tool definition drift.
- SSE integration testing.
- MCP config-file scanning.
- Terminal inventory view.

## v0.1.0-alpha.1 - 2026-06-05

Initial alpha release candidate.

### Added

- `mcpscan` CLI with `scan`, `list-checks`, and `version` commands.
- stdio MCP enumeration using the official Python MCP SDK.
- tested Streamable HTTP remote scan path using a local fixture server.
- deterministic static checks for prompt injection, dangerous capabilities, secret exposure, sensitive file/data exposure, command/code injection surfaces, unauthenticated remote enumeration, missing TLS, and static known-name lookalikes.
- terminal, JSON, and Markdown reporters.
- safe finding evidence model with `payload_stored=false`.
- benign, malicious, and Streamable HTTP MCP fixture servers.
- GitHub Actions CI for Python 3.11 and 3.12.

### Deferred

- MCP-002 tool definition drift.
- dynamic probing.
- HTML reports.
- registry monitoring.
- GitHub Action packaging.
- SaaS dashboards and runtime enforcement.
