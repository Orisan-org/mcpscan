# Changelog

## Unreleased

### Added

- Added a wheel test harness (`tests/test_wheel_install.py`, `pytest -m wheel`) that
  builds the wheel, installs it into a clean unconstrained virtualenv, and runs the
  headline commands from the installed console script against real fixture servers.
  Every other test runs against the repo tree, which is why bug 3 shipped unseen.
- Added an mcp SDK version guard (`src/mcpscan/sdk_compat.py`). When the dependency
  pin is bypassed, `scan` and `scan-config` refuse and name the installed version
  instead of producing a scan that silently omits a transport. `version` and
  `list-checks` still work, so a broken environment can be reported.

### Fixed

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
command remain `mcpscan`). Full test suite green on Python 3.11-3.14. All entries
below shipped in 0.1.0.

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
