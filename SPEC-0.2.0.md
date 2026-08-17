# SPEC-0.2.0 — static-first, signed, and drift-aware

Status: **draft for approval. Do not build yet.**
Against: `orisan-mcpscan` 0.1.1 (`9649575`)

This spec covers six target capabilities, in the priority order given. Read
section 0 first: two of the six are substantially already built, and one cannot
be delivered as written.

---

## 0. Conflicts with existing design

These are the things to settle before any slice starts. Each names the code
that creates the conflict.

### C1 — "full findings from config alone" is not achievable, and the gap is structural

**This is the important one.**

Every description-based check reads `ctx.tools`:

| Check | Reads |
|---|---|
| `ToolDescriptionPromptInjectionCheck` | `ctx.tools[].description` |
| `SecretExposureInMetadataCheck` | `ctx.tools[].description` |
| `DangerousCapabilityExposureCheck` | `ctx.tools[].description` |
| `CommandInjectionSurfaceCheck` | `ctx.tools[].input_schema` |
| `SensitiveDataExposureCheck` | `ctx.tools[].description` |
| `LookalikeNameCheck` | `ctx.server.name`, `ctx.tools[].name` |

`ctx.tools` is populated by a connector calling `tools/list`. That requires the
server to be **running**. An MCP config file contains a command, arguments,
environment variable names, and for remote entries a URL and headers. It does
not contain a single tool description — those live inside the server and are
only knowable by asking it.

So "full findings from config alone" is not a scheduling problem. Six of nine
checks have no input in that mode. Shipping it as written would mean a scan that
returns few or no findings on a genuinely malicious server and reports success,
which is the false-assurance failure mode this project exists to avoid.

**Proposed resolution — three evidence tiers, named in every report.**

| Tier | Input | Executes? | Network? | Checks that can run |
|---|---|---|---|---|
| `config` | MCP config JSON | no | no | transport, TLS, auth, env-name secrets, server-name lookalike, config drift |
| `surface` | a stored surface snapshot | no | no | all nine, against the captured surface |
| `live` | a running server | yes | yes | all nine, against the current surface |

Tier `surface` is what actually delivers the intent behind item 1: full findings,
no execution, CI-friendly. It needs the surface to have been captured once —
by someone, at some point, on a machine willing to run the server — which is
exactly the artefact slice 7's `snapshot` produces. **Items 1 and 3 are the same
feature seen from two ends**, and building them in the stated order is wrong;
`snapshot` has to come first or tier `surface` has no input.

A tier-`config` report must state, per check, that it did not run and why. That
follows the existing no-suppression invariant: a check that could not run is not
a check that passed.

### C2 — SARIF (item 4) already ships

`src/mcpscan/reporters/sarif.py` emits SARIF 2.1.0 with the schema URL, tool
driver version, and `rules` built from `check_catalogue()`. Covered by
`tests/test_sarif.py` and `tests/test_sarif_parity.py`.

The real gap is narrower: `scan-config` accepts only `table, terminal, json, md,
markdown` — **there is no `sarif` output on the config path at all**, which is
the path CI would use. Item 4 is re-scoped in slice 8 to parity plus tier
reporting, not a new reporter.

### C3 — OWASP MCP Top 10 mapping (item 5) already ships

`OWASP_MCP_REFERENCES` in `capabilities.py` carries MCP01–MCP10 complete, and
`owasp_reference()` is already applied to findings. Item 5 is re-scoped in slice
9 to what is genuinely missing: the mapping surfaced in SARIF `properties`, and
a coverage report saying which of the ten a given scan actually exercised —
which in tier `config` will be most of them not exercised.

### C4 — drift (item 3) is half-built, and the half that is missing is the one that matters

Present: `SurfaceSnapshot`, `SurfaceItem` (sha256 of normalised description and
key-sorted schema), `compare_tool_surface()` producing MCP-002 findings for tool
added / removed / description changed, wired to `--baseline` and
`--baseline-dir`, covered by `tests/test_surface_drift.py`.

Missing:

1. No `snapshot` or `drift` subcommand — drift is a side effect of a full scan,
   so you cannot check for drift without re-running everything.
2. **`SurfaceSnapshot` has no launch command.** It hashes tools, resources and
   prompts. A rug pull that leaves every tool description intact and swaps
   `command` from `uvx thing` to `uvx thing --exfil` is invisible to it today.
   The user's own third dimension — "command changed" — is the one not covered.
3. No stable snapshot file format or version negotiation, so a snapshot is
   currently just a full JSON report used as a baseline.

### C5 — signing introduces the first crypto dependency, and the witness call is network

mcpscan has no crypto today (`grep` for ed25519/nacl/sign finds nothing in
`src/`). Slice 5 adds one. Two constraints follow:

- Witness submission must be **opt-in and off by default**, in the same shape as
  the existing `--push-envelope`. The no-telemetry invariant is stated as "the
  single outbound-reporting path is the opt-in `--push-envelope` flag"; adding a
  second one means that sentence in the README must be updated to name both, or
  the invariant is quietly false.
- Key generation must not happen implicitly during a scan. A scan that silently
  writes a private key to disk is a surprise, and on a shared CI runner it is a
  liability.

### C6 — "byte identical" contradicts the current report

The README already qualifies determinism as "byte-identical apart from the run
timestamp", and reports carry one. A signed record cannot include a wall-clock
field and also be byte-reproducible.

Resolution: the signature covers a **verdict body** that excludes all
non-reproducible fields. Timestamp, duration, hostname and target string live
outside the signed body, in an envelope. "Same input, same output, byte
identical" then means: same signed body, and the same signature bytes, because
Ed25519 is deterministic. That is a testable claim; "the whole file is
identical" is not.

### C7 — `--format orisan` (item 6) crosses a repo boundary and cannot produce a valid chain alone

Recorder schema v3 rejects unknown event fields and unknown `kind` values
outright — `ALLOWED_EVENT_KEYS` and `EVENT_KINDS` in `orisan-recorder/src/schema.ts`.
There is no `scan_finding` kind. Worse, a recorder event is only meaningful
inside a hash chain: it needs `seq`, `prev_hash` and `hash` continuous with the
events around it.

So mcpscan cannot emit standalone "recorder events" that are actually valid. Two
honest options, and slice 10 needs a decision before it starts:

- **(a) Append into a real log directory.** mcpscan takes `--orisan-log <dir>`
  and appends through the recorder's own store. Requires the recorder writer
  lock (recorder #1), makes mcpscan depend on a Node artefact from a Python
  process, and means a scan mutates an evidence log.
- **(b) Emit a detached findings document** in recorder *vocabulary* — same
  field names, same canonical JSON, same digest rules — explicitly labelled as
  not chained, for the recorder to ingest later. No cross-process locking, no
  false claim of being chain-verified.

**(b) is recommended.** (a) sounds tighter and is worse: it puts a scanner
inside the trust boundary of the evidence log.

### C8 — SARIF regions can leak what `payload_stored=false` promises

SARIF supports `snippet` inside `physicalLocation.region`. Any future work that
populates it from server-supplied text would put raw payload into the report
while the finding still says `payload_stored=false`. Slice 8 adds a test that
forbids it rather than relying on nobody doing it.

### C9 — cross-platform items already in the tree

`config_scanner` discovers Claude Desktop, Claude Code, Cursor and Windsurf
config paths; snapshot files add a second path-resolution surface. Anything
slice 7 writes must use the platform config dir, not a hardcoded `~/.mcpscan`,
and snapshot writes need to be atomic (temp file plus rename) because a
half-written baseline silently becomes a drift false positive.

---

## 1. Invariants — unchanged, and enforced

Every slice inherits these. They are not goals, they are constraints, and a
slice that cannot meet one stops rather than bending it.

- **Deterministic.** No randomness, no wall-clock, no network state in the
  verdict.
- **No LLM anywhere in the verdict path.**
- **No suppression.** A finding is shown, escalated, held or annotated. A check
  that could not run is reported as not run, never as passed.
- **`payload_stored=false`** on every finding, in every output format.
- **No telemetry.** Nothing leaves the machine without an explicit flag.
- **Severity is never lowered by anything the scanned server said.**
- **No claim about any competitor's accuracy** in README, docs, help text,
  commit messages or release notes. Enforced by a test, not by discipline —
  see slice 0.

---

## Slice 0 — the documentation guard

Small, first, because it constrains every slice after it.

**Goal.** Make the competitor-accuracy rule mechanical.

**Design.** `tests/test_no_competitor_claims.py` scans `README.md`, `docs/**`,
`SECURITY.md`, `CHANGELOG.md` and CLI help strings for a list of competitor
names, and fails if one appears within a configurable window of a comparative
accuracy term (`false positive`, `misses`, `more accurate`, `better than`,
`fails to detect`, `catches more`, …).

Naming a competitor factually is allowed ("Ramparts emits SARIF"). Rating one is
not.

**Acceptance tests.**

- **A0.1** A doc containing "mcp-scan has a high false positive rate" fails the test.
- **A0.2** A doc containing "Ramparts emits SARIF 2.1.0" passes.
- **A0.3** The test scans its own source, so the competitor list cannot be
  emptied without the test noticing (same pattern as the recorder's domain
  allowlist test).
- **A0.4** Every current doc in the tree passes.

**Done when** the guard runs in CI and the existing docs pass unmodified.

---

## Slice 1 — evidence tiers

**Goal.** Make "what could this scan actually see" a first-class field, before
anything depends on it.

**Design.** `EvidenceTier = config | surface | live` on `ScanContext` and on the
report. Every `Check` in the registry declares `requires: set[EvidenceTier]`.
The engine runs a check only if the context's tier satisfies it, and records a
`CheckNotRun` entry with the reason for every check it skipped.

`--no-execute` on both `scan` and `scan-config` forces tier `config`, and the
process **never spawns a subprocess or opens a socket** in that mode.

**Non-goals.** No new checks. No change to any existing check's logic.

**Acceptance tests.**

- **A1.1** With `--no-execute`, no subprocess is spawned and no socket opened.
  Asserted by monkeypatching `subprocess.Popen` and `socket.socket` to raise —
  the scan must still complete.
- **A1.2** A tier-`config` report lists all six description-dependent checks as
  not run, each with a reason naming the missing input.
- **A1.3** `checks_not_run` is non-empty in tier `config` and empty in tier
  `live` for the benign fixture server.
- **A1.4** The grade in tier `config` is never `A`. A scan that could not look at
  a single tool description has not earned a clean grade. (Decide: a distinct
  grade band, or a suffix. Recommend a separate `graded_on` field naming the
  tier, and refusing to print a bare letter without it.)
- **A1.5** Terminal, JSON, Markdown and SARIF all state the tier.
- **A1.6** Tier appears in the JSON report at a stable top-level key.

**Done when** every existing test still passes and tier is visible in all four
formats.

---

## Slice 2 — the config-only check set

**Goal.** Make tier `config` worth running.

**Design.** Checks that can run on config alone, and which today either need a
live context or do not exist:

- `UnauthenticatedRemoteServerCheck`, `MissingTLSCheck` — already config-derivable
  from the URL; make them tier-`config` capable.
- `LookalikeNameCheck` — runs on the server name from config, without tool names.
  Must report reduced confidence, not silently weaker coverage.
- **New:** env-variable-name secret heuristics (names only — values are already
  redacted and must stay that way).
- **New:** launch-command supply-chain signals: unpinned `npx`/`uvx` package
  specifiers, `@latest`, a git URL, a bare `curl … | sh`.
- **New:** `NODE_TLS_REJECT_UNAUTHORIZED=0` and equivalent transport-disabling
  env values.

**Acceptance tests.**

- **A2.1** A config with `"command": "npx", "args": ["-y", "thing@latest"]`
  produces an unpinned-dependency finding at tier `config`, mapped to MCP04.
- **A2.2** A config with a pinned version produces no such finding.
- **A2.3** `NODE_TLS_REJECT_UNAUTHORIZED=0` produces a finding mapped to MCP07.
- **A2.4** Env **values** never appear in any output; names and counts only.
  Asserted against a config whose env value is a distinctive sentinel string.
- **A2.5** `http://` remote entries produce the TLS finding with no server running.
- **A2.6** Every new finding sets `payload_stored=false` and carries an OWASP id.
- **A2.7** Two runs over the same config produce byte-identical findings.

---

## Slice 3 — surface replay

**Goal.** Tier `surface`: all nine checks, no execution. This is what item 1 was
actually asking for.

**Design.** `mcpscan scan --from-surface <file>` builds a `ScanContext` from a
stored snapshot instead of a connector.

The blocker: `SurfaceSnapshot` stores **hashes only** (by design — it is a
privacy feature). Hashes cannot be pattern-matched, so a replay scan from
today's snapshot format can detect drift and nothing else.

Therefore snapshots need two profiles, and the choice must be explicit at
capture time:

- `hashes` (default, today's behaviour) — drift only.
- `full` — retains normalised descriptions and schemas, enabling replay of all
  nine checks. Larger, and it contains server-supplied text, so it is a file the
  operator must choose to create and is marked as containing untrusted content.

**Acceptance tests.**

- **A3.1** A `full` snapshot of the poisoned fixture, replayed with
  `--from-surface`, produces the identical finding set to a `live` scan of the
  same server. Byte-identical after removing the envelope.
- **A3.2** Replay spawns no subprocess and opens no socket (same harness as A1.1).
- **A3.3** Replaying a `hashes` snapshot does not silently degrade: it refuses,
  naming the profile mismatch, and exits non-zero.
- **A3.4** A `full` snapshot is marked in-file as containing untrusted
  server-supplied text.
- **A3.5** A snapshot with an unknown `surface_version` is refused, not
  best-effort parsed.

---

## Slice 4 — ruleset versioning and the determinism harness

**Goal.** Make "same input, same output" a pinned, testable property before
anything is signed over it.

**Design.** A `RULESET_VERSION` derived from the check catalogue: id, version and
a digest of each check's pattern data. Bumping any pattern bumps the ruleset
digest. Reports carry `ruleset_version` and `ruleset_digest`.

**Acceptance tests.**

- **A4.1** Changing one regex in one check changes `ruleset_digest`.
- **A4.2** Reordering checks in the registry does **not** change it.
- **A4.3** The same input scanned twice produces identical verdict bodies,
  compared byte for byte after the envelope is stripped.
- **A4.4** The same input scanned on a different Python patch version produces
  the same digest. (CI matrix; flag if dict ordering or `re` behaviour makes
  this fail — better to know now.)
- **A4.5** A test asserts the catalogue has no check whose pattern data is
  loaded from the network or the environment.

---

## Slice 5 — the signed result record

**Goal.** A verdict a third party can check without trusting the machine that
produced it.

**Design.** `ScanResult` = envelope + signed body.

Signed body contains: ruleset version and digest, evidence tier, target
identity (a digest of the normalised target, not the raw string), the surface
digest, the full finding list in canonical order, checks-not-run, grade, and
mcpscan version. It contains **no** timestamp, duration, hostname, or path.

Envelope contains those, unsigned, and the signature.

Ed25519 via `cryptography`. Canonical JSON identical in rules to the recorder's
(sorted keys, no incidental whitespace) so one verifier can read both.

Keys: `mcpscan keygen` writes a keypair explicitly, mode 0600. A scan without a
key emits an **unsigned** record and says so in the output — it does not
generate a key as a side effect, and it does not fail.

`mcpscan verify-result <file> [--pubkey <pem>]` checks the signature and
re-derives the body digest; exit 0 verified / 1 signature bad / 2 cannot verify,
matching the recorder's exit-code contract.

**Acceptance tests.**

- **A5.1** Two scans of the same input with the same key produce **byte-identical
  signed bodies and byte-identical signatures** (Ed25519 is deterministic).
- **A5.2** Envelope fields differ between those two runs (timestamps) and that
  does not affect the signature.
- **A5.3** Editing any byte of the body fails `verify-result` with exit 1.
- **A5.4** Editing an envelope field does **not** invalidate the signature, and
  `verify-result` says which fields are outside the signature.
- **A5.5** A body signed under ruleset digest X fails to reproduce under ruleset
  digest Y, and the message names both.
- **A5.6** No key present → unsigned record, exit code unchanged, output states
  it is unsigned. No key file is created.
- **A5.7** `verify-result` on an unsigned record exits 2, never 0.
- **A5.8** The private key is never written to a report, log line, or error message.
- **A5.9** Key file permissions are 0600 on POSIX; on Windows the check is
  skipped with an explicit reason rather than silently passing.

---

## Slice 6 — optional witness submission

**Goal.** Let a scan result be externally timestamped, using the witness that
already exists.

**Design.** `--witness <url>` submits the signed body digest to
`witness.orisan.org` (or any URL given), pinning the witness key at first use in
the same shape as `orisan-rec witness register`. Off by default. Never runs
without the flag.

The witness stores a digest and a signature. It must not receive findings,
target strings, tool names, or anything else about the scanned system — that
would turn an opt-in integrity feature into the telemetry the project promises
not to have.

**Acceptance tests.**

- **A6.1** Without `--witness`, no outbound connection is attempted. Asserted by
  a socket monkeypatch that raises.
- **A6.2** The submitted payload contains only the body digest, ruleset digest
  and signature. Asserted field-by-field against an allowlist, so adding a field
  later breaks the test.
- **A6.3** A witness that is unreachable does not fail the scan; the result is
  written and marked unwitnessed.
- **A6.4** A witness key that does not match the pinned one aborts loudly and
  does not submit.
- **A6.5** A 429 or 503 from the witness is retried with backoff and reported as
  deferred, not as a refusal. (Matches recorder behaviour; reuse the semantics.)

---

## Slice 7 — `snapshot` and `drift`

**Goal.** Rug-pull detection as a first-class operation, including the dimension
currently missing.

**Design.**

```
mcpscan snapshot <target|--config <path>> --out <file> [--profile hashes|full]
mcpscan drift --baseline <file> [<target>|--config <path>|--from-surface <file>]
```

`SurfaceSnapshot` gains a `launch` block: the normalised command, argument
vector, env variable **names**, transport, and remote URL — hashed in the
`hashes` profile, retained in `full`. This closes C4.2: a config whose command
changed is drift even when every tool description is identical.

`drift` reports per change: `tool_added`, `tool_removed`, `description_changed`,
`schema_changed`, `command_changed`, `args_changed`, `env_names_changed`,
`url_changed`, `transport_changed`. Exit 0 no drift / 1 drift / 2 cannot compare.

`drift` against a `--from-surface` input executes nothing, which makes this the
CI-safe mode.

**Acceptance tests.**

- **A7.1** Adding a tool between snapshots reports exactly `tool_added` and names it.
- **A7.2** Changing one character of one description reports `description_changed`
  and nothing else.
- **A7.3** **Changing the launch command with every description identical reports
  `command_changed`.** This is the case today's code cannot see.
- **A7.4** Adding an env variable name reports `env_names_changed`; changing an
  env **value** reports nothing and leaks nothing.
- **A7.5** No change reports no drift and exits 0.
- **A7.6** Comparing snapshots of two different servers refuses with exit 2
  rather than reporting everything as drift.
- **A7.7** Mismatched `surface_version` exits 2.
- **A7.8** Snapshot writes are atomic: a killed process leaves either the old
  file or the new one, never a truncated file. Tested by killing mid-write.
- **A7.9** Snapshot files are byte-identical for two snapshots of an unchanged
  server, so they can be committed to a repo and diffed.
- **A7.10** `drift` on Windows path separators behaves identically.

---

## Slice 8 — SARIF completion

**Goal.** Close the actual gaps rather than rewriting a working reporter.

**Design.** `--output sarif` on `scan-config`. Evidence tier and
`checks_not_run` represented in SARIF — the latter as `invocation.toolExecutionNotifications`
or explicit `rules` with no results, so a CI reader can tell "clean" from
"not looked at". OWASP id in each result's `properties`.

**Acceptance tests.**

- **A8.1** `scan-config --output sarif` produces output that validates against
  the SARIF 2.1.0 schema.
- **A8.2** Parity: the same findings appear in SARIF and JSON for the config
  path, matching the existing `test_sarif_parity.py` approach.
- **A8.3** A tier-`config` SARIF file distinguishes not-run checks from passing
  checks, and a reader consuming only SARIF can tell them apart.
- **A8.4** **No SARIF `region.snippet` field is ever populated.** Guards C8.
- **A8.5** Each result carries its OWASP MCP id in `properties`.
- **A8.6** SARIF output is byte-identical across two runs of the same input,
  once the envelope timestamp is excluded.

---

## Slice 9 — OWASP coverage reporting

**Goal.** Say which of the ten a scan actually exercised.

**Design.** A coverage block: for each of MCP01–MCP10, `exercised` /
`not_exercised_in_this_tier` / `no_check_implemented`. The third value is the
honest one and is expected to be non-empty.

Checks today emit **MCP01, 02, 03, 05, 07, 09, 10**. Three categories have the
reference text in `capabilities.py` but no check behind them:

| Category | Status |
|---|---|
| MCP04 supply chain risk | no check today; **slice 2 closes it** with the unpinned-specifier signals |
| MCP06 tool shadowing | no check today, and none proposed in this spec |
| MCP08 audit and logging gaps | no check today, and none proposed in this spec |

Having the reference string present makes the mapping look complete when it is
not, which is exactly the kind of overstatement this project forbids. Slice 9
exists to make that visible rather than to fix it.

**Acceptance tests.**

- **A9.1** Coverage block present in JSON and SARIF.
- **A9.2** A tier-`config` scan shows most categories `not_exercised_in_this_tier`.
- **A9.3** Any category with no implemented check is reported as
  `no_check_implemented`, derived from the registry rather than a hand-written
  list, so it stays truthful as checks are added.
- **A9.3b** With the tree as it stands, that set is exactly {MCP06, MCP08} after
  slice 2 lands, and {MCP04, MCP06, MCP08} before it. A test pins this so a
  category cannot silently move to `exercised` without a check behind it.
- **A9.4** Adding a check that maps to a new category updates coverage with no
  other change.

---

## Slice 10 — `--format orisan`

**Goal.** Findings the recorder can ingest, without pretending to be chained
evidence.

**Design.** Per C7, option (b): a detached findings document using recorder
vocabulary and canonical JSON, explicitly `chained: false`, with no `seq`,
`prev_hash` or `hash` fields invented. The recorder ingests it and assigns chain
position at append time.

**Decision required before this slice starts:** whether `orisan-recorder`'s
`EVENT_KINDS` gains a `scan_finding` kind. That is a change in another repo,
covered by that repo's own process, and this slice is blocked on it.

**Acceptance tests.**

- **A10.1** Output contains no `seq`, `prev_hash` or `hash` field.
- **A10.2** `chained: false` is present and a consumer that ignores it cannot
  mistake the document for a verified chain.
- **A10.3** Canonical JSON matches the recorder's rules exactly: same key
  ordering, same escaping, byte-identical for equal input.
- **A10.4** Every emitted item validates against the recorder's event schema
  once chain fields are added by the recorder.
- **A10.5** `payload_stored=false` survives the mapping.

---

## Sequencing

The stated priority order is not a valid build order. Two changes:

1. **Slice 7 (`snapshot`) must precede slice 3 (surface replay)**, because
   replay has no input until snapshots exist. Item 1's real payload therefore
   lands after item 3's, even though item 1 ranks higher.
2. **Slice 4 (ruleset versioning) must precede slice 5 (signing)**, because
   signing a verdict whose ruleset is unidentified is signing an unreproducible
   claim.

Recommended order: **0 → 1 → 2 → 4 → 7 → 3 → 5 → 6 → 8 → 9 → 10.**

Slices 8 and 9 are small and could move earlier if a CI-integration
demonstration is needed sooner; they do not block anything.

---

## What this spec does not do

- No new detection capability beyond the config-tier checks in slice 2. This is
  a distribution, reproducibility and trust release, not a coverage release.
  MCP06 (tool shadowing) and MCP08 (audit and logging gaps) still have no check
  when it ships, and slice 9 will say so on every report.
- No change to any existing check's logic, severity, or adjudication.
- No sandboxing of live execution. Tier `live` still runs the server with the
  operator's privileges; static-first reduces how often that is necessary but
  does not make it safe. If sandboxing is wanted, it is a separate spec.
- No claim, anywhere, about how any other scanner performs.
