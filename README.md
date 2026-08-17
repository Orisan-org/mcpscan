# mcpscan

**mcpscan finds the security risks in a Model Context Protocol (MCP) server — dangerous tools, leaked secrets, injection surfaces, unsafe transport — and grades them, before an AI agent ever trusts that server. It runs entirely on your machine.**

> Installs from PyPI as **`orisan-mcpscan`**; the command it gives you is `mcpscan` (an `orisan-mcpscan` alias also works). It is an alpha.

## Try it in ten seconds

No repo of your own, no MCP servers to configure. [uvx](https://docs.astral.sh/uv/) fetches mcpscan and runs it in one step, against a bundled sample config that includes one benign server and one deliberately risky one:

```bash
uvx orisan-mcpscan scan-config examples/sample-mcp.json --yes
```

Run it from a checkout of this repo (the only file you need is `examples/sample-mcp.json`). From a bare machine, grab just that file first:

```bash
curl -sO https://raw.githubusercontent.com/Orisan-org/mcpscan/main/examples/sample-mcp.json
uvx orisan-mcpscan scan-config sample-mcp.json --yes
```

The first run downloads the two sample servers via `npx` (~30s cold); after that it is seconds.

Real output — the risky server, which is handed the whole filesystem, grades **D**:

```text
Servers: 2 total, 2 scanned, 0 failed, 0 skipped
Worst grade: D

notes-memory
  Transport: stdio
  Purpose: memory_store (config)
  Grade: A
  No findings.

risky-filesystem
  Transport: stdio
  Purpose: filesystem (config)
  Grade: D
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ SEVERITY ┃ VERDICT              ┃ ID      ┃ TARGET              ┃ FINDING                                         ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ expected_unconfirmed │ MCP-010 │ edit_file           │ Tool 'edit_file' appears to expose file write   │
│ HIGH     │ expected_unconfirmed │ MCP-010 │ get_file_info       │ Tool 'get_file_info' appears to expose read     │
│ HIGH     │ expected_unconfirmed │ MCP-010 │ read_file           │ Tool 'read_file' appears to expose file read    │
│ HIGH     │ expected_unconfirmed │ MCP-010 │ read_multiple_files │ Tool 'read_multiple_files' exposes file read    │
│ HIGH     │ expected_unconfirmed │ MCP-010 │ write_file          │ Tool 'write_file' appears to expose file write  │
└──────────┴──────────────────────┴─────────┴─────────────────────┴─────────────────────────────────────────────────┘

Privacy: payload_stored=false for all findings
```

How to read it:

- **`Purpose: filesystem (config)`** — mcpscan worked out what the server is *for* from the config entry, and says where that came from. What follows depends on that source.
- **`expected_unconfirmed`** — file read and write are exactly what a filesystem server is for, so they are not treated as hidden capability. But you did not confirm that purpose: the config line could have been copy-pasted from the server's own README. So mcpscan holds severity at **HIGH** rather than either escalating it or waving it through. Confirm with `--purpose-category filesystem` and these drop to `INFO (was HIGH)`.
- **Severity is never lowered by anything the scanned server had a hand in saying.** Raising it is open to any source; lowering it requires you. That one rule is why the same tool can be both quiet on a legitimate server and loud on a lying one.
- Nothing is hidden or suppressed — every finding is shown, escalated, held, or annotated.
- The benign `notes-memory` server grades **A** with no findings, so a clean server looks clean.

## What it does, and what it does not do

**What it does**

- **Local-only.** It runs on your machine. It does not upload source code, prompts, secrets, raw MCP responses, or findings to Orisan or anyone else. The only network it touches is the MCP server you point it at.
- **No LLM in the verdict path.** Every check, severity, verdict, and grade is deterministic pattern and heuristic logic. No model call decides whether something is a finding or what grade you get. (You can grep the codebase for `openai`/`anthropic`/`llm` and find nothing in the scan path.)
- **Deterministic.** The same server produces the same verdict every time — byte-identical apart from the run timestamp. No randomness, no wall-clock, in the verdict.
- **No telemetry.** No analytics, no phone-home, no usage beacons. The single outbound-reporting path is the **opt-in `--push-envelope` flag**, which POSTs a shared report envelope to a control-plane URL *you* provide; without that flag nothing leaves the machine.
- **No suppression, no stored payloads.** It never drops a finding to make a server look cleaner; it escalates or annotates instead. Every finding carries redacted evidence only and sets `payload_stored=false`.

**What it does not do (yet)**

- **No fleet scanning.** One config or target per run. There is no multi-host inventory, dashboard, or continuous monitoring.
- **No dependency / supply-chain scanning.** It inspects the MCP server's exposed surface (tools, resources, prompts, metadata), not the server's package tree or its dependencies.
- **No IDE extension.** Command-line only; there is no editor or browser integration.
- It also does not secure the model, enforce runtime policy, block agent actions, modify the target server, or monitor package registries.

---

## Install

`uvx orisan-mcpscan …` (above) needs no install. To install the command persistently:

```bash
pipx install orisan-mcpscan     # or: uv tool install orisan-mcpscan
mcpscan --help
```

From a cloned repo, for development:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
mcpscan list-checks
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py"   # grade A, no findings
```

## Scan your client configs

`scan-config` starts from an MCP client config instead of a single server command:

```bash
mcpscan scan-config ./mcp.json --yes
mcpscan scan-config ./.mcp.json --yes --output json --out report.json
```

Config shape (the standard `mcpServers` object):

```json
{
  "mcpServers": {
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe"] },
    "remote-dev": { "url": "http://127.0.0.1:8000/mcp" }
  }
}
```

`scan-config` scans config paths you pass explicitly, and can also discover known local MCP config locations for **Claude Desktop, Claude Code, Cursor, and Windsurf**. Stdio entries prompt before local execution unless `--yes` is given; remote URL entries never prompt. Environment values are passed to stdio servers but redacted from all output (names/counts only).

Use `--push-envelope` to POST the shared Orisan envelope to a control plane (URL from `--control-plane-url` or `ORISAN_CONTROL_PLANE_URL`, default `http://127.0.0.1:8787`; bearer via `--ingest-token`/`ORISAN_INGEST_TOKEN`). This is the only outbound-reporting path and it is off by default.

## Scan a single server (stdio or HTTP)

```bash
# stdio: launches the command locally, handshakes, enumerates, then checks it.
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py"

# Streamable HTTP (the primary tested remote transport):
mcpscan scan http://127.0.0.1:8000/mcp --transport http
```

Stdio targets execute locally — only scan commands you are willing to run. Cold-start `npx`/`uvx` servers can take 30+ seconds on first run; the default timeout is 90s (`--timeout` to change).

## Reports and exit codes

```bash
mcpscan scan --command "…" --output json  --out report.json
mcpscan scan --command "…" --output md    --out report.md
mcpscan scan --command "…" --output sarif --out report.sarif   # SARIF 2.1.0 for CI/code-scanning
```

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; no finding met the severity threshold |
| `1` | Scan completed; at least one finding met the threshold |
| `2` | User input / CLI usage error, including a `scan-config` run where nothing was scanned |
| `3` | Connection or enumeration error |
| `4` | Internal scanner error |

`--severity-threshold low|medium|high|critical` controls when findings return exit `1`.

| Transport | Status |
| --- | --- |
| stdio | Tested |
| Streamable HTTP | Tested |
| SSE | Wired through the MCP SDK when available; not integration-tested |

## Context-aware verdicts (no suppression)

mcpscan never suppresses a finding. It labels each with a deterministic contextual verdict and keeps both original and adjusted severity when they differ:

- `expected_by_purpose` — inherent to a purpose **you** supplied; downgrade-eligible (e.g. `INFO (was HIGH)`).
- `expected_unconfirmed` — inherent to a purpose mcpscan inferred but you did not confirm. Severity is left exactly as the check set it: not escalated, and not lowered.
- `unexpected` — outside the purpose category, but mentioned in declared text.
- `undeclared` — outside the purpose category and not mentioned; treated as worse (e.g. `CRITICAL (was HIGH)`).
- `unadjudicated` — no purpose was available.

The one rule behind all of it: **any purpose source may raise a severity; only a purpose you supplied may lower one.** Raising needs no trust — the worst a hostile source achieves by escalating is making its own findings look worse. Lowering is a claim that a dangerous capability is fine, so it has to come from outside the thing being scanned.

| Purpose source | Where it comes from | May lower a severity? |
| --- | --- | --- |
| `flag` | `--purpose` / `--purpose-category` | Yes |
| `invocation` | the command line or URL you typed | Yes |
| `config` | a command line or URL read from an MCP client config file | No |
| `server_info` | the server's own name and instructions | No |

`config` is excluded on purpose even though it usually *is* your intent: install snippets get copy-pasted out of server-authored documentation, so the same string can be the server talking. `server_info` is the server talking outright — one that names itself `filesystem-helper` must not be able to make its own file-write capability look routine.

Confirm an inferred purpose with `--purpose-category` when you want the downgrade. Taxonomy in [docs/PURPOSE_TAXONOMY.md](docs/PURPOSE_TAXONOMY.md).

## What mcpscan checks

| ID | Title | Base severity | OWASP MCP | Status |
| --- | --- | --- | --- | --- |
| MCP-001 | Tool description prompt injection | high | MCP03 | active |
| MCP-002 | Tool definition drift | high | MCP03 | active with `--baseline` |
| MCP-010 | Dangerous capability exposure | high | MCP02 | active |
| MCP-020 | Secret exposure in metadata | critical | MCP01 | active |
| MCP-021 | Sensitive data / file exposure | high | MCP10 | active |
| MCP-030 | Command or code injection surface | high | MCP05 | active |
| MCP-040 | Unauthenticated remote server | high | MCP07 | active |
| MCP-041 | Missing TLS | high | MCP07 | active |
| MCP-050 | Known-name lookalike (curated seed list) | medium | MCP09 | active |
| MCP-060 | Secret value in configured environment | critical | MCP01 | active, all tiers |
| MCP-061 | Dangerous launch command or configuration | high | MCP05 | active, all tiers |
| MCP-062 | Unpinned server package | medium | MCP04 | active, all tiers |
| MCP-063 | Broad filesystem path granted in configuration | high | MCP02 | active, all tiers |

### SARIF

`--output sarif` on both `scan` and `scan-config`, SARIF 2.1.0.

- The OWASP MCP Top 10 is declared as a **taxonomy**, with `isComprehensive:
  false` because three categories have no check. Every result points into it by
  taxon reference and every rule declares its relationship, so a consumer reads
  the category from the structure rather than from a string property it has to
  know about. Each taxon carries its coverage status, derived from the registry.
- Every result carries its **evidence tier**, not just the run: `scan-config`
  produces one run over several servers and they need not share one.
- **Checks that did not run** appear as `toolExecutionNotifications` on the
  invocation, identically for both commands, so a reader can tell *clean* from
  *not looked at*.
- No `region.snippet` is ever populated. SARIF permits server-supplied text
  there, and every finding says `payload_stored=false`.

### Signed results

    mcpscan keygen
    mcpscan scan --command "uvx thing@1.2.3" --sign-result result.json
    mcpscan verify-result result.json --pubkey mcpscan.pub

The signature covers a **verdict body** that excludes everything
non-reproducible: wall-clock, hostname, paths, duration. Those sit in an
unsigned envelope, and `verify-result` prints which fields are outside the
signature so nobody assumes otherwise.

That split is what makes "same input, same output, byte identical" testable
rather than a slogan. Ed25519 is deterministic, so the same body under the same
key produces the same 64 signature bytes every time — a body with a timestamp in
it never could. The **ruleset version and digest are inside the signed body**: a
verdict whose ruleset is unidentified is not reproducible, whatever it is signed
with.

The target is recorded as a **digest, not a command line**. A command line can
contain a home directory, which names a person, and a signed record is the thing
most likely to be forwarded to someone who should not learn it.

Keys are never created by a scan. `mcpscan keygen` writes one deliberately, mode
600 from the moment it exists. A scan with no key writes an **unsigned** record
and says so on stderr; it does not generate key material as a side effect, which
on a shared CI runner would be a liability rather than a convenience.

`verify-result` exits **0** verified, **1** tampered, **2** cannot verify. An
unsigned record is always 2 — never 0, because "we verify our scans" must not
quietly become untrue.

#### Witnessing a result (optional)

    mcpscan witness register --url https://witness.orisan.org
    mcpscan scan --command "uvx thing@1.2.3" --sign-result result.json --witness

A signature proves who said something. It does not prove **when**, and it cannot
prove an inconvenient result was not quietly deleted. Submitting the verdict's
digest to a witness outside your control closes both.

The witness receives, exhaustively: a random log id, an index, the body digest,
and the signature over those. It never receives findings, grades, target
strings, tool names, commands or paths. The payload is built from an allowlist
rather than by filtering, so adding a field to the record cannot leak it, and a
test asserts the exact field set. The log id is a random UUID and does not
encode the target.

The witness key is **pinned** at registration and never updated from a response.
A different key later is an attack, not a rotation.

None of this is required. No witness, an unreachable witness or a throttled one
all leave the scan and its signature standing; the result is marked unwitnessed
and says why. Without `--witness` nothing is contacted at all, which is asserted
by a test that makes every outbound call raise.

### Snapshot and drift

    mcpscan snapshot --command "uvx thing@1.2.3" --out thing.snapshot.json --label thing
    mcpscan drift --baseline thing.snapshot.json --command "uvx thing@1.2.3"

A rug pull is a change made *after* you approved a server, so a one-shot scan
structurally cannot see it. `snapshot` records the surface; `drift` says what
moved.

The snapshot records the **launch** as well as the tool surface: the executable,
the argument vector, the environment variable **names**, the transport and the
URL. That closes the case a tool comparison misses entirely — every description
byte-identical, and `uvx thing` quietly replaced by `uvx thing --exfil`.

Drift reports tool added, tool removed, description changed, schema changed,
launch executable changed, launch arguments changed, environment names changed,
transport changed and URL changed.

Environment **values** are never recorded or compared, not even as hashes: a
hash of a secret is an oracle for guessing it. A changed value is invisible here
by design, and the report says so.

Exit codes: **0** no drift, **1** drift, **2** cannot compare. Comparing two
snapshots with different labels is refused rather than reported as
every-tool-changed, which is operator error dressed as a catastrophe.
`--against <snapshot>` compares two files and executes nothing, which is the
CI-safe mode. A baseline captured before the launch block existed reports that
the launch was **not compared**, rather than reporting no change.

Snapshot files carry no timestamp and are byte-identical for an unchanged
server, so they can be committed and diffed like a lockfile. Writes are atomic;
a temp file left by a killed process is swept by the next write.

### Ruleset version and digest

Every report carries `ruleset_version` and `ruleset_digest`, and `mcpscan
ruleset` prints them without running a scan. The scanner version pins the code;
the digest pins the **rules**, and a pattern change is what moves a verdict.
"mcpscan 0.1.1 said B" is not a reproducible claim on its own.

The digest is taken over a canonical manifest of every check's metadata and
every module-level constant in its defining module — patterns, keyword lists,
thresholds — sorted by check id, so reordering the registry does not change it
but changing any rule does. `mcpscan ruleset --manifest` prints exactly what is
hashed.

**What it does not cover:** logic written inline rather than as data. Changing
`if len(x) > 3` to `> 5` inside a check moves verdicts without moving the
digest. The mitigation is a convention — thresholds live in module constants,
where the manifest can see them — not a guarantee. Hashing bytecode would close
the gap and would also change with every Python release, which would make the
digest useless for the thing it exists for.

### Evidence tiers

Every report states which tier produced it, and lists the checks that tier could
not supply inputs for.

| Tier | Input | Starts the server | Network |
|---|---|---|---|
| `config` | an MCP config file | no | no |
| `surface` | a captured surface snapshot | no | no |
| `live` | a running server | yes | yes |

`--no-execute` forces tier `config` on both `scan` and `scan-config`: nothing is
started, nothing is contacted. Tool descriptions and schemas do not exist in a
config file — they live inside the server — so the six checks that read them are
reported as **not run, with the reason**, never as passing.

A grade is **withheld** when any check did not run. `grade` is `null` in JSON,
`grade_assessed` is `false`, and the terminal prints
`not assessed (config tier, N check(s) did not run)`. An annotated `A` still
reads as an A to someone skimming, and a config-tier scan of a hostile server
would otherwise score one.

MCP-060 to MCP-063 read the configuration rather than the tool surface, so they
run at **every** tier — including with `--no-execute`. A config that pipes a
remote script into a shell, hands over a home directory, or carries a live
credential is a finding before any server starts.

These are **configuration findings** and are deliberately outside purpose
adjudication. A declared purpose cannot make a credential in the environment
appropriate, and a filesystem server being expected to read files must not
excuse it being handed every file you own. Their severity is neither raised nor
lowered by the declared purpose; the verdict reads `unadjudicated` with the
reason.

Environment **values** are matched but never emitted — not masked, not
truncated. The report names the variable and the pattern class only.

**Tier `surface`** replays a stored snapshot, so every check runs with nothing
started:

    mcpscan snapshot --command "uvx thing@1.2.3" --profile full --out thing.json
    mcpscan scan --tier surface --from-snapshot thing.json

It needs `--profile full`. The default `hashes` profile is for drift: a digest
cannot be pattern-matched, so replaying it would run every check against empty
text and report nothing found. A hashes-only snapshot is **refused** rather than
replayed into a quiet result. A full snapshot retains server-supplied text and
is a different thing to keep on disk, which is why it is opt-in.

Every replay report names the snapshot and when it was taken, in JSON, terminal
and markdown, because a report that does not say lets a stale snapshot pass for
a current scan:

    Replayed from: thing.json
      captured 2026-08-17T10:50:40+00:00 (3d ago) — findings describe the
      surface AS CAPTURED, not as it is now

A replay finds exactly what a live scan of the same server finds; that parity is
asserted against the malicious fixture on every test run.

    mcpscan coverage

prints which of MCP01–MCP10 have a check, what each check actually inspects,
and which tiers it runs at — derived from the registry, so it cannot claim a
category nothing checks. It is the answer to give a security review, and it
says no where the answer is no:

    Uncovered: MCP06, MCP08. These are not partially covered or planned;
    nothing in mcpscan looks at them today.

Coverage maps to OWASP MCP classes MCP01, MCP02, MCP03, MCP04, MCP05, MCP07, MCP09, MCP10. MCP06 (tool shadowing) and MCP08 (audit/logging) are out of scope for this alpha. MCP04 coverage is launch-specifier pinning only (MCP-062); dependency trees and package provenance are still not inspected. MCP-002 runs only with `--baseline`/`scan-config --baseline-dir`. MCP-050 is an offline heuristic against a curated static seed list, not registry monitoring.

## Privacy and evidence model

By default mcpscan runs locally and uploads nothing. Findings store safe, redacted evidence only — location and class of risk, never full raw payloads — and every finding sets `payload_stored=false`. JSON reports include a `surface` block of hash-only snapshots (descriptions whitespace-normalized, schemas key-sorted, before hashing). Do not put secrets in `--command`, headers, or output paths; reports may echo the target string for traceability.

## Development

```bash
ruff format --check . && ruff check . && pytest
python -m mcpscan --help
pytest -m network   # network-dependent stdio checks, excluded from default pytest
```

## License

MIT
