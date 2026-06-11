# mcpscan Build Plan v1.0

Date: 2026-06-11
Status: Approved for execution
Repo: github.com/Orisan-org/mcpscan (Python, src layout, pytest, ruff)

This document is the complete build specification. Execute slices strictly in
order. Do not start slice N+1 until every acceptance criterion of slice N
passes by actually running the listed commands. Do not ask the founder
questions that this document answers. If you hit a genuine ambiguity this
document does not cover, make the smallest reasonable decision, record it in
`docs/DECISIONS.md` with date and rationale, and continue.

---

## 0. Working agreement for the coding agent

1. One slice per working session / PR. Branch name `slice-NN-short-name`.
2. Before claiming a slice done, run all quality gates AND all slice
   acceptance commands. Paste real output into the PR description or
   `docs/DECISIONS.md`. Never mark a criterion passed without running it.
3. Quality gates (must pass on every slice):
   ```
   ruff format --check .
   ruff check .
   pytest
   python -m mcpscan --help
   python -m mcpscan list-checks
   ```
4. Update `CHANGELOG.md` per slice (Keep a Changelog style, Unreleased
   section).
5. Hard rules, no exceptions:
   - No LLM calls anywhere in the scanner. All logic deterministic.
   - Never suppress a finding. Adjudication may change severity, never
     delete findings.
   - `payload_stored=false` invariant holds for every finding.
   - No telemetry, no network calls except to the MCP target being scanned
     (and explicit corpus/competitor tooling which is dev-only).
   - No scope bleed into other Orisan tools (relay, scout, guard, review).
   - Match existing code style and module layout. Read the existing code in
     `src/mcpscan/` before writing; where this plan's assumed file names
     differ from reality, follow reality and note the mapping in
     `docs/DECISIONS.md`.
6. Dependency policy: stdlib + existing dependencies preferred. PyYAML is
   approved for the data files in this plan. `jsonschema` is approved for
   dev/test dependencies only. Nothing else without a DECISIONS.md entry
   explaining why.
7. Python version: whatever `pyproject.toml` currently declares. Do not
   raise it.
8. Platform: develop and test on Linux/macOS. Windows support is
   best-effort path handling, no Windows CI required.

---

## 1. Background and intent (read once, it informs every choice)

mcpscan is a local-first, deterministic MCP server security scanner. The
strategy is to win on accuracy and decision-grade reporting, not breadth:

- Every other scanner (Snyk agent-scan, Cisco MCP Scanner, agentsec,
  Invariant mcp-scan) emits context-blind capability findings. A shell
  capability is flagged identically on a shell-executor server (where it is
  the product) and on a weather server (where it is an attack surface).
- mcpscan's differentiator: a deterministic, purpose-conditioned
  adjudication layer that labels each finding `expected_by_purpose`,
  `unexpected`, `undeclared`, or `unadjudicated`, and adjusts severity
  accordingly, with the reasoning printed.
- The proof is a labeled corpus of real public MCP servers and a published
  precision/recall benchmark comparing mcpscan against competitors.
- Determinism is a marketed property: identical input must produce
  identical output, byte-for-byte where feasible (sort findings, fixed key
  order in JSON, no timestamps inside findings themselves).

Phases: Slices 1-4 are the credibility floor. Slices 5-8 are the
differentiator. Slices 9-12 are the benchmark proof.

---

## SLICE 1: Fix stdio enumeration (timeout wiring + error unwrapping)

### Problem (from cold audit AUDIT2, 2026-06-07)

- `--timeout` is a no-op for stdio: the value reaches
  `StdioConnector.__init__` but `asyncio.wait_for` is never applied to the
  handshake. Cold-start `npx` servers (15-35s before handshake) fail 100%.
- Failures surface as `EnumerationError("...unhandled errors in a TaskGroup
  (1 sub-exception)")` because the raised `ExceptionGroup` is stringified
  instead of unwrapped. `remote.py` (~line 142) already has a
  BaseExceptionGroup special-case; stdio does not.
- Default timeout in `cli.py` (~line 76) is 20.0 seconds.

### Implementation

1. In the stdio connector (`src/mcpscan/connectors/stdio.py`), wrap the
   entire connect + `ClientSession.initialize()` + enumeration block in
   `asyncio.wait_for(..., timeout=self.timeout_seconds)`.
2. Catch `asyncio.TimeoutError` (and `TimeoutError`) separately and raise:
   ```
   EnumerationError(
     f"stdio handshake timed out after {self.timeout_seconds:.0f}s. "
     "Cold-start npx/uvx servers can take 30+ seconds on first run. "
     "Retry, or raise --timeout."
   )
   ```
3. Create a shared helper `unwrap_exception_group(exc) -> BaseException` in
   the errors module (or wherever EnumerationError lives) that recursively
   descends `BaseExceptionGroup.exceptions[0]`-style nesting to the
   innermost real exception. Refactor BOTH `stdio.py` and `remote.py` to use
   it. The user-facing message must contain the innermost exception's type
   and message, never the words "TaskGroup".
4. Change the default timeout in `cli.py` from `20.0` to `90.0`. Update
   `--help` text accordingly.
5. Add test fixture `tests/fixtures/slow_server.py`: a minimal stdio MCP
   server that sleeps `--delay N` seconds (default 5) before completing the
   initialize handshake, then behaves like `benign_server.py`.

### Tests (all spawn real subprocesses, no mocked ScanContext)

- `tests/test_stdio_integration.py`:
  - Scan `benign_server.py` end-to-end via the public CLI entry path
    (`CliRunner` or `subprocess`); assert exit code 0 and grade A output.
  - Scan `malicious_server.py`; assert exit code 1 and findings present.
  - Scan `slow_server.py --delay 5` with `--timeout 2`; assert exit code 3,
    stderr/stdout contains "timed out after 2s" and does NOT contain
    "TaskGroup".
  - Scan `slow_server.py --delay 2` with `--timeout 30`; assert success
    (proves the timeout is a ceiling, not a sleep).
  - Scan a command that exits immediately with garbage (e.g.
    `python -c "print('not mcp')"`); assert exit code 3 and the error names
    the real cause, not "TaskGroup".
- `tests/test_stdio_network.py`, marked `@pytest.mark.network` and excluded
  from default pytest run (register the marker in pyproject): scan
  `npx -y @modelcontextprotocol/server-filesystem /tmp` with defaults;
  assert completion. Document in README dev section how to run it.

### Acceptance criteria

- [ ] All quality gates pass; full existing suite still green.
- [ ] `mcpscan scan --command "npx -y @modelcontextprotocol/server-filesystem /tmp"`
      succeeds on a cold npm cache with default flags (run manually, record
      output).
- [ ] Timeout test produces the clean message; no ExceptionGroup text can
      reach a user from either connector (grep the codebase: the only place
      stringifying an ExceptionGroup is inside `unwrap_exception_group`).
- [ ] Default timeout shown as 90s in `--help`.
- [ ] README updated: the quickstart stays as-is; add one sentence to the
      stdio section noting cold-start npx guidance.

---

## SLICE 2: Check metadata (capability classes + OWASP MCP Top 10 mapping)

### Goal

Every check, and every emitted finding, carries a machine-readable
`capability` and OWASP MCP Top 10 mapping. This is the substrate for
adjudication (slice 6) and benchmark scoring (slice 10).

### Capability enum (create `src/mcpscan/capabilities.py`)

```
class Capability(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_EGRESS = "network_egress"
    SHELL_EXEC = "shell_exec"
    CODE_EVAL = "code_eval"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXPOSURE = "data_exposure"
    PROMPT_ANOMALY = "prompt_anomaly"
    TRANSPORT_SECURITY = "transport_security"
    IDENTITY_SPOOF = "identity_spoof"
    SURFACE_DRIFT = "surface_drift"
    OTHER = "other"
```

### Default mapping (verify against actual check implementations; adjust if
a check's real detection logic differs, and record in DECISIONS.md)

| Check | Default capability | OWASP MCP Top 10 |
|---|---|---|
| MCP-001 prompt injection in descriptions | PROMPT_ANOMALY | MCP03 |
| MCP-002 tool definition drift | SURFACE_DRIFT | MCP03 |
| MCP-010 dangerous capability exposure | per-finding (see below) | MCP02 |
| MCP-020 secret exposure in metadata | CREDENTIAL_ACCESS | MCP01 |
| MCP-021 sensitive data/file exposure | DATA_EXPOSURE | MCP10 |
| MCP-030 command/code injection surface | SHELL_EXEC or CODE_EVAL | MCP05 |
| MCP-040 unauthenticated remote server | TRANSPORT_SECURITY | MCP07 |
| MCP-041 missing TLS | TRANSPORT_SECURITY | MCP07 |
| MCP-050 lookalike name | IDENTITY_SPOOF | MCP09 |

MCP-010 and MCP-030 must set capability per finding based on what was
actually detected (e.g. a filesystem-write tool -> FILE_WRITE; an eval
parameter -> CODE_EVAL). Each check class gets a `default_capability`; the
finding emission path accepts an override.

### Implementation

1. Add `capability: Capability` and `owasp_mcp: str` (e.g. "MCP05") fields
   to the Finding model. Include both in JSON and Markdown output.
2. Add the same as class attributes / metadata on each check, surfaced in
   `mcpscan list-checks` output (new columns).
3. Keep `reference` (the human-readable OWASP string) for backward
   compatibility, but derive it from `owasp_mcp` via a lookup table in one
   place.

### Tests

- Every active check has non-null capability and owasp_mcp (parametrized
  test over the check registry).
- Scanning `malicious_server.py` yields findings whose capability matches
  the fixture's known tools (assert at least one SHELL_EXEC or CODE_EVAL).
- JSON report contains the new fields; `list-checks` shows them.

### Acceptance criteria

- [ ] Quality gates pass.
- [ ] `mcpscan list-checks` shows capability and OWASP columns for all checks.
- [ ] README "What mcpscan Checks" table updated with the OWASP MCP Top 10
      column, and a short paragraph stating which of the ten OWASP MCP
      classes are covered and which are explicitly out of scope (MCP04
      supply chain, MCP06 intent flow, MCP08 audit/telemetry are out of
      scope for now; say so plainly).

---

## SLICE 3: Config auto-discovery (`scan-config`)

### Goal

Users do not know their server launch commands; they have client config
files. `mcpscan scan-config` parses well-known MCP client configs and scans
every server in them. This is the single biggest adoption gap vs Snyk
agent-scan.

### Config locations (auto-discovery order; also accept an explicit path arg)

| Client | Path(s) |
|---|---|
| Claude Desktop | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`; Linux: `~/.config/Claude/claude_desktop_config.json`; Windows: `%APPDATA%/Claude/claude_desktop_config.json` |
| Claude Code | `./.mcp.json` (project), `~/.claude.json` (mcpServers key) |
| Cursor | `./.cursor/mcp.json` (project), `~/.cursor/mcp.json` (global) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

All use the de-facto `mcpServers` object shape: stdio entries have
`command` + `args` (+ optional `env`), remote entries have `url` (+ optional
`headers`). Parse defensively; skip and warn on entries you cannot parse,
never crash.

### CLI behavior

```
mcpscan scan-config                # auto-discover all known configs
mcpscan scan-config PATH           # scan one specific config file
  --yes                            # skip consent prompts (CI use)
  --only NAME[,NAME]               # scan only named servers
  --output / --out / --timeout / --severity-threshold  # same as scan
```

- For each stdio server: print the EXACT command + args that will be
  executed and prompt `Execute and scan? [y/N]` (default No). `--yes`
  bypasses. This consent flow is a security feature; do not weaken it.
  Declined servers are recorded in the report as `skipped (no consent)`.
- Remote (`url`) servers are scanned without any prompt (no local
  execution).
- `env` values from the config are passed to the subprocess but MUST be
  redacted in all output (show key names only, e.g. `env: API_KEY=<redacted>`).
- Output: one combined report containing a per-server section. Exit code 1
  if ANY scanned server has findings meeting the threshold; exit 3 only if
  ALL servers failed to enumerate; partial failures are reported per-server
  and do not abort the run.

### Tests

- Fixture configs under `tests/fixtures/configs/` covering: one stdio
  benign server, one stdio malicious server, one unreachable remote, one
  malformed entry. Test with `--yes`.
- Consent prompt test: without `--yes`, simulate `n` input; assert the
  server is skipped, marked in the report, and nothing was executed.
- Env redaction test: a config with `env: {SECRET: hunter2}`; assert
  "hunter2" appears nowhere in any output format.

### Acceptance criteria

- [ ] Quality gates pass.
- [ ] `mcpscan scan-config tests/fixtures/configs/mixed.json --yes` scans
      both fixture servers in one run, reports per-server, exit 1.
- [ ] Redaction test green; grep proves secrets never reach output.
- [ ] README gets a "Scan Your Client Configs" section directly after the
      quickstart (this becomes the new headline use case).

---

## SLICE 4: Surface snapshot + drift detection (activate MCP-002)

### Goal

Rug-pull / drift detection. A scanner positioned as "scan before you trust"
must detect that a server changed since last scan.

### Implementation

1. Every JSON report gains a `surface` block: for each tool/resource/prompt,
   record `name`, `description_sha256` (sha256 of the description after
   normalizing whitespace), and `schema_sha256` (sha256 of the
   canonical-JSON-serialized input schema, sorted keys). No raw descriptions
   beyond what findings already store. This block is the baseline format;
   version it `surface_version: 1`.
2. New flag: `mcpscan scan ... --baseline PREVIOUS_REPORT.json`. When
   provided, after enumeration compare current surface to baseline and emit
   MCP-002 findings (severity high) for: tool added, tool removed,
   description changed, schema changed. Evidence states what changed by
   name and hash prefix, never the raw old/new text.
3. Flip MCP-002 status from `deferred` to `active`. It only fires when
   `--baseline` is supplied; document that.
4. `scan-config` (slice 3) gets `--baseline-dir DIR`: reads/writes one
   baseline file per server name in DIR, enabling
   "rescan my whole client config and tell me what changed".

### Tests

- Two fixture variants: `benign_server.py` and a `benign_server_v2.py`
  (one description changed, one tool added). Scan v1 -> save report -> scan
  v2 with `--baseline` -> assert exactly the expected MCP-002 findings.
- Self-drift test: scan v1, baseline against its own report, assert zero
  MCP-002 findings (hashing is stable).

### Acceptance criteria

- [ ] Quality gates pass.
- [ ] Drift demo runs end-to-end as above with correct findings.
- [ ] README: drift section with the two-command workflow; check table row
      MCP-002 flips to active.

---

## SLICE 5: Purpose profile

### Goal

Build a structured, deterministic "what does this server claim to be"
profile per scan. Substrate for slice 6.

### Purpose categories (create data file `src/mcpscan/data/purpose_categories.yaml`)

Categories: `filesystem`, `database`, `shell_execution`, `code_execution`,
`browser_automation`, `api_wrapper`, `web_search`, `communication`,
`dev_tools`, `memory_store`, `unknown`.

The YAML maps each category to:
- `keywords`: lowercase substrings matched against the declared text
  (e.g. filesystem: [filesystem, file system, "read file", "write file",
  directory, fs]). Write 5-10 solid keywords per category; favor precision
  over recall, `unknown` is an acceptable outcome.
- `expected_capabilities`: list of Capability values considered inherent to
  the category. Initial table:

| Category | expected_capabilities |
|---|---|
| filesystem | FILE_READ, FILE_WRITE, DATA_EXPOSURE |
| database | DATA_EXPOSURE, NETWORK_EGRESS |
| shell_execution | SHELL_EXEC, FILE_READ, FILE_WRITE |
| code_execution | CODE_EVAL, FILE_READ |
| browser_automation | NETWORK_EGRESS, DATA_EXPOSURE |
| api_wrapper | NETWORK_EGRESS |
| web_search | NETWORK_EGRESS |
| communication | NETWORK_EGRESS, DATA_EXPOSURE |
| dev_tools | FILE_READ, FILE_WRITE, SHELL_EXEC |
| memory_store | DATA_EXPOSURE, FILE_WRITE |
| unknown | (empty) |

This file is public, documented, and PR-able; add a short
`docs/PURPOSE_TAXONOMY.md` explaining how to propose changes.

### Profile construction (new module `src/mcpscan/purpose.py`)

Inputs, in priority order (higher wins for category; all declared text is
concatenated for the declared-text corpus used in slice 6):
1. CLI flags: `--purpose-category CATEGORY` (enum-validated) and
   `--purpose "free text"`.
2. Server `serverInfo.name` + `serverInfo.instructions` (or the SDK's
   equivalent fields) from the initialize result.
3. Nothing -> category `unknown`.

Category inference from text: lowercase the declared text, count keyword
hits per category, pick the category with the most hits; ties or zero hits
-> `unknown`. Fully deterministic, no scoring magic.

The profile object: `{category, category_source: flag|server_info|unknown,
declared_text, expected_capabilities}`. It appears in JSON and Markdown
reports.

### Tests

- Flag overrides serverInfo. serverInfo inference works for a fixture whose
  instructions say "filesystem server for reading and writing files".
- Garbage/empty text -> unknown. Tie -> unknown.
- YAML loads, all expected_capabilities values are valid Capability members
  (schema test so taxonomy PRs cannot break the build).

### Acceptance criteria

- [ ] Quality gates pass.
- [ ] Scanning `benign_server.py` with
      `--purpose-category filesystem` shows the profile in all output
      formats.
- [ ] `docs/PURPOSE_TAXONOMY.md` exists and README links to it.

---

## SLICE 6: Deterministic contextual adjudicator

### Goal

The differentiator. Each finding gets a contextual verdict and an adjusted
severity, with one-line reasoning. No LLM. Nothing suppressed.

### Verdicts

`expected_by_purpose` | `unexpected` | `undeclared` | `unadjudicated`

### Downgrade eligibility (hard table, enforce in code + test)

Only capability-exposure checks may ever be downgraded:

| Check | Downgrade-eligible? |
|---|---|
| MCP-010 | yes |
| MCP-030 | yes |
| MCP-021 | yes, only when category == filesystem or database |
| MCP-001, MCP-002, MCP-020, MCP-040, MCP-041, MCP-050 | NEVER (prompt injection, drift, secrets, transport, spoofing are bad regardless of purpose) |

### Adjudication logic (module `src/mcpscan/adjudicate.py`)

For each finding F with capability C, given profile P:

1. If P.category == unknown and no `--purpose` text was given:
   verdict = `unadjudicated`; severity unchanged; reasoning
   "No declared purpose available; pass --purpose or --purpose-category to
   enable contextual adjudication."
2. Else if C in P.expected_capabilities AND F's check is downgrade-eligible:
   verdict = `expected_by_purpose`; adjusted_severity = `info`
   (new severity level below `low` if one does not exist; add it);
   reasoning "Capability {C} is inherent to declared purpose
   '{P.category}'. Reported for completeness."
3. Else if C not in P.expected_capabilities:
   - Build `capability_keywords`: a small static map in
     `purpose_categories.yaml` from each Capability to declaration
     keywords (e.g. NETWORK_EGRESS: [http, url, fetch, request, api]).
   - If any keyword for C appears in P.declared_text:
     verdict = `unexpected`; severity unchanged; reasoning
     "Capability {C} is outside the expected set for '{P.category}' but is
     mentioned in the server's declared text."
   - Else: verdict = `undeclared`; adjusted_severity = one level above
     original, capped at critical; reasoning "Capability {C} is neither
     expected for '{P.category}' nor mentioned anywhere in the declared
     text. Possible hidden capability."
4. Non-downgrade-eligible checks always keep original severity; they still
   get a verdict label per rules 1/3 for reporting, but rule 2's downgrade
   never applies.

Finding model gains: `original_severity`, `adjusted_severity`,
`contextual_verdict`, `verdict_reasoning`. Exit-code thresholding and the
grade computation use `adjusted_severity`. Terminal/MD/JSON show both
severities when they differ.

### Tests (the demo trio, plus edges)

- Filesystem fixture scanned with `--purpose-category filesystem`: its
  file-access MCP-010 finding -> expected_by_purpose, info.
- Same capability on a fixture declaring "weather server":
  -> undeclared, escalated.
- Fixture declaring "weather server that can fetch URLs" with a
  NETWORK_EGRESS finding -> unexpected, unchanged.
- MCP-020 secrets finding on a filesystem server -> severity NEVER
  downgraded (test the hard table).
- No purpose info -> all unadjudicated, byte-identical to pre-slice-6
  severities.
- Determinism: run the same scan twice, assert identical JSON
  (excluding scan timestamp metadata).

### Acceptance criteria

- [ ] Quality gates pass.
- [ ] Demo trio reproducible via three documented commands; add them to the
      README under "Context-Aware Verdicts" with example output. This
      section is the marketing centerpiece; keep claims exactly as true as
      the tests prove.
- [ ] Grep-level proof that no code path deletes findings.

---

## SLICE 7: Report v2 (decision-grade output)

### Goal

A report a security engineer can forward internally without edits.

### JSON schema v2 (top-level shape; write the actual JSON Schema file at
`src/mcpscan/data/report.schema.json` and validate in tests)

```
{
  "report_version": "2.0",
  "scan": {
    "mcpscan_version", "checks_version", "timestamp_utc",
    "target" (redacted command or URL), "transport",
    "timeout_seconds", "reproduce_command"
  },
  "server": { "name", "version", "transport", "source": null },
  "purpose_profile": { ... slice 5 object ... },
  "verdict_summary": {
    "recommendation": "proceed" | "proceed_with_conditions" | "do_not_connect",
    "grade": existing A-F,
    "counts_by_adjusted_severity": {...},
    "top_findings": [up to 3 one-line plain-language strings]
  },
  "surface": { ... slice 4 block ... },
  "findings": [ full finding objects, sorted by (adjusted_severity desc,
                check id, target) ],
  "not_checked": [ static strings, see below ],
  "skipped_servers": [ scan-config only ]
}
```

Recommendation rule (deterministic): any adjusted critical ->
`do_not_connect`; else any adjusted high -> `proceed_with_conditions`; else
`proceed`.

`not_checked` static list (ship in code, update as features land):
"Server source code is not analyzed", "Runtime behavior is not observed",
"Dependencies/supply chain are not audited", "Drift requires --baseline
rescans", "Registry squatting coverage limited to a curated seed list".

### Markdown report v2 (five blocks, in order)

1. Identity & provenance: server name/version, target, transport, mcpscan +
   checks versions, timestamp, exact `reproduce_command`,
   `payload_stored=false` statement.
2. Verdict summary: recommendation, grade, purpose profile one-liner, top
   findings in plain blast-radius language ("This server can execute
   arbitrary shell commands and never declares it").
3. Findings table: adjusted severity, verdict, capability, OWASP ID, check
   ID, target, one-line evidence; full evidence + remediation + reasoning
   below the table per finding.
4. What we did not check: render `not_checked`.
5. Reproduce: the exact command(s).

Golden-file tests for both JSON (schema-validated, stable key order) and
Markdown (snapshot of malicious fixture with a purpose flag).

### Acceptance criteria

- [ ] Quality gates pass; `jsonschema` validation of emitted reports in
      tests.
- [ ] Markdown report for the malicious fixture contains all five blocks
      (assert headers exist).
- [ ] README example output updated to v2.

---

## SLICE 8: SARIF 2.1.0 output

- New `--output sarif`. Map: ruleId = check ID; rules metadata from the
  check registry (name, shortDescription, helpUri = OWASP reference);
  level: critical/high -> error, medium -> warning, low/info -> note;
  result.properties carries capability, owasp_mcp, contextual_verdict,
  original_severity.
- Vendor the SARIF 2.1.0 JSON schema into `tests/data/` (no network in
  tests) and validate emitted SARIF against it.
- Acceptance: gates pass; malicious-fixture SARIF validates; README output
  table mentions SARIF; a minimal GitHub Action usage snippet added to
  `docs/CI.md` showing upload via `github/codeql-action/upload-sarif`.

---

## SLICE 9: Corpus harness

### Goal

Reproducible machinery to scan a pinned set of real public servers. The
founder selects servers and writes labels; this slice is tooling only.

### Artifacts

1. `corpus/manifest.yaml`: list of entries
   `{id, name, repo_url, git_sha, stratum: reference|popular|risky|dual_nature,
   category, install: [shell steps], launch_command, transport, notes}`.
   Ship with 2 real example entries (use the modelcontextprotocol reference
   filesystem and memory servers at pinned SHAs) plus a schema-validation
   test for the manifest format.
2. `scripts/run_corpus.py`:
   - Clones each repo at its SHA into `.corpus-cache/` (gitignored), runs
     install steps in an isolated venv per server, launches the scan via
     the normal CLI with `--output json`, writes
     `corpus/results/{id}/mcpscan-{version}.json` plus `run.log`.
   - Per-server failures recorded in `corpus/results/{id}/error.txt`; never
     abort the whole run.
   - Deterministic ordering; final summary table to stdout.
   - SECURITY: print a banner that corpus servers execute locally and the
     harness should run in a container/VM; require an `--i-understand`
     flag.
3. Marked manual/network; not part of default pytest.

### Acceptance criteria

- [ ] Manifest schema test green.
- [ ] `python scripts/run_corpus.py --i-understand` completes against the 2
      example entries on a dev machine (record output).
- [ ] `docs/CORPUS.md` documents the manifest format, how to add a server,
      and the container recommendation.

---

## SLICE 10: Ground truth + scoring tooling

### Goal

Label format and metric computation. Ground truth attaches to SERVER
PROPERTIES, not to any scanner's finding format, so the benchmark is
scanner-agnostic and the referee-and-player criticism is answerable.

### Artifacts

1. Label schema, one file per server: `corpus/labels/{server_id}.yaml`
   ```
   server_id: ...
   corpus_sha: <git_sha from manifest>
   labeler: <name or handle>
   label_date: YYYY-MM-DD
   properties:
     - property_id: <server_id>-P01
       capability: shell_exec            # Capability enum value
       tool: run_command                 # or null for server-level
       label: real_threat | by_design | benign
       evidence: >
         Written reasoning: what the capability is, what the declared
         purpose implies, external evidence (docs/advisory/paper link),
         why this label.
       external_refs: [urls]
   ```
   `benign` means the property exists but is neither a threat nor notable
   (used to score false positives: a scanner finding that maps to no
   real_threat property and no by_design property counts as FP).
2. Mapping rules `corpus/mapping/{scanner_name}.yaml`: how a scanner's
   finding (check/rule id + capability/keywords) maps to ground-truth
   properties. mcpscan's own mapping uses (capability, tool) match.
3. `scripts/score_corpus.py`:
   - Inputs: labels dir, normalized results dir (slice 11 format; mcpscan's
     own JSON is normalized via a built-in adapter).
   - Outputs per scanner: TP/FP/FN, precision, recall, F1, overall and per
     stratum; plus mcpscan-only verdict accuracy: % of by_design
     properties that mcpscan adjudicated expected_by_purpose, % of
     real_threat properties kept at high/critical.
   - Writes `corpus/results/scores.md` (table) and `scores.json`.
4. Validation: schema tests for label and mapping files; a toy labeled set
   under `tests/fixtures/corpus_toy/` with hand-computed expected metrics
   asserted exactly.

### Acceptance criteria

- [ ] Toy-set metrics match hand calculations exactly.
- [ ] Malformed label files rejected with a clear error.
- [ ] `docs/BENCHMARK_METHOD.md` skeleton created with sections:
      Conflict of interest statement (first section, the founder writes the
      text), Preregistration, Label freeze (records the git commit hash of
      the frozen labels), Inter-rater reliability, Dispute process,
      Reproduction.

---

## SLICE 11: Competitor adapters

### Goal

Run competitors against the same corpus and normalize their output for
scoring. These tools must be installed locally; everything here is
manual/dev tooling, no CI.

### Adapters (one module each under `scripts/adapters/`)

| Scanner | Pin | Invocation sketch | Output to normalize |
|---|---|---|---|
| Snyk agent-scan | latest release at time of run, record exact version | scan the corpus server's config; consent flags per its docs | its JSON/terminal findings |
| Cisco MCP Scanner | exact version recorded | per its CLI docs | its findings output |
| agentsec | exact version recorded | per its CLI docs | its SARIF/JSON |
| Invariant mcp-scan | exact version recorded | per its docs | its JSON |

Each adapter: (a) documents the EXACT install + invocation commands in its
docstring, (b) writes raw output verbatim to
`corpus/results/{server_id}/{scanner}-{version}.raw`, (c) normalizes to a
common shape `{scanner, version, server_id, findings: [{rule_id, title,
severity, target, capability_guess}]}` written alongside as `.normalized.json`.
Normalization rules live in the slice-10 mapping YAMLs, not hardcoded.

If a competitor cannot run against a given server (transport unsupported,
crash), record that fact in the raw output dir; it is itself a benchmark
data point.

### Acceptance criteria

- [ ] Each adapter produces raw + normalized output on at least 3 corpus
      servers on a dev machine (record outputs in the repo under
      corpus/results, raw files included).
- [ ] Exact versions and commands recorded in `docs/BENCHMARK_METHOD.md`.
- [ ] Scoring script (slice 10) ingests the normalized files end-to-end.

---

## SLICE 12: Benchmark publication scaffolding + README truth pass

1. Complete `docs/BENCHMARK_METHOD.md` structure; founder fills prose.
2. `docs/PREREGISTRATION.md`: corpus selection criteria, strata quotas,
   label schema, and metrics, committed BEFORE full corpus scanning begins
   (the founder triggers this; the file template is the deliverable).
3. README truth pass: re-read every claim in README and docs against what
   the code now provably does. Fix or delete anything not backed by a test
   or a recorded run. Add a "Benchmarks" section that links to the
   methodology and says "results pending corpus v1" until real numbers
   exist. Never publish placeholder numbers.
4. Acceptance: a cold read of the README by the founder (or a fresh agent
   session given only the repo) finds zero claims that cannot be
   demonstrated with a command from the README itself.

---

## DEFERRED (do not build; listed so you do not improvise them)

- LLM-based annotation of findings (slice 13, unscheduled). The scanner
  stays deterministic.
- Registry monitoring, SaaS dashboard, HTML reports, GitHub Action
  packaging beyond the docs/CI.md snippet, runtime enforcement, dynamic
  probing/sandboxed execution, skills scanning.
- Anything touching orisan-relay, orisan-scout, orisan-guard, orisan-review.

---

## Anticipated questions, pre-answered

1. "The codebase differs from the plan's assumed file names." Follow the
   codebase; record the mapping in docs/DECISIONS.md; do not restructure
   modules to match the plan.
2. "Should I add typer/click/rich/etc?" Use whatever CLI framework the repo
   already uses. No new frameworks.
3. "Severity enum has no info level." Add it below low; update grade and
   threshold logic so info never trips exit 1 and never lowers a grade.
4. "What timestamp format?" ISO 8601 UTC, in scan metadata only, never
   inside findings; exclude it from determinism comparisons.
5. "JSON key ordering?" Emit with sorted or explicitly fixed key order so
   diffs are stable; document choice in DECISIONS.md.
6. "Windows config paths fail in tests?" Guard with platform checks; only
   POSIX paths need test coverage.
7. "serverInfo.instructions not exposed by the SDK version pinned?" Use
   whatever initialize-result fields the pinned MCP SDK exposes; if
   instructions is unavailable, fall back to name only and note it.
8. "Backwards compatibility of report v1?" Not required. Alpha product,
   report_version bumps to 2.0, CHANGELOG notes the break.
9. "May I bump the MCP SDK dependency?" Only if a slice is impossible
   without it; record exact old/new versions and why in DECISIONS.md.
10. "Found a bug outside the current slice?" File it as a TODO in
    docs/DECISIONS.md and stay in-slice, unless it blocks the slice's
    acceptance criteria.

---

## Definition of done for the whole plan

`mcpscan scan-config --yes` works against real client configs; cold-start
npx servers scan with default flags; drift detection works across rescans;
every finding carries capability, OWASP ID, contextual verdict, and
reasoning; reports ship in terminal/JSON/Markdown/SARIF with the five
decision-grade blocks; the corpus, scoring, and competitor harnesses run
end-to-end; and every README claim is demonstrably true from a command in
the README. Benchmark numbers are published only after the founder freezes
labels and runs the full corpus.
