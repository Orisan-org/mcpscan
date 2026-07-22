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

Real output — the risky server, which is handed broad filesystem access, grades **F**:

```text
Servers: 2 total, 2 scanned, 0 failed, 0 skipped
Worst grade: F

notes-memory
  Transport: stdio
  Purpose: memory_store (server_info)
  Grade: A
  No findings.

risky-filesystem
  Transport: stdio
  Purpose: filesystem (server_info)
  Grade: F
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ SEVERITY            ┃ VERDICT    ┃ ID      ┃ TARGET              ┃ FINDING                                        ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL (was HIGH) │ undeclared │ MCP-010 │ edit_file           │ Tool 'edit_file' appears to expose file write  │
│ CRITICAL (was HIGH) │ undeclared │ MCP-010 │ write_file          │ Tool 'write_file' appears to expose file write │
│ HIGH                │ unexpected │ MCP-010 │ get_file_info       │ Tool 'get_file_info' appears to expose read    │
│ HIGH                │ unexpected │ MCP-010 │ read_file           │ Tool 'read_file' appears to expose file read   │
│ HIGH                │ unexpected │ MCP-010 │ read_multiple_files │ Tool 'read_multiple_files' exposes file read   │
└─────────────────────┴────────────┴─────────┴─────────────────────┴────────────────────────────────────────────────┘

Privacy: payload_stored=false for all findings
```

How to read it:

- **`CRITICAL (was HIGH)`** — the write tools are escalated from their base HIGH to CRITICAL. The number after "was" is always the original severity, so you can see exactly what context changed and why.
- **`undeclared` vs `unexpected`** — `write_file`/`edit_file` are `undeclared`: the server's stated purpose never mentioned writing files, so unannounced write access is treated as worse. The read tools are `unexpected`: outside the declared purpose but at least visible in it. Nothing is hidden or suppressed — every finding is shown, escalated or not.
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
| `2` | User input / CLI usage error |
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

- `expected_by_purpose` — inherent to the declared purpose; downgrade-eligible (e.g. `INFO (was HIGH)`).
- `unexpected` — outside the purpose category, but mentioned in declared text.
- `undeclared` — outside the purpose category and not mentioned; treated as worse (e.g. `CRITICAL (was HIGH)`).
- `unadjudicated` — no declared purpose was available.

Provide purpose with `--purpose "…"` or `--purpose-category filesystem`; otherwise server metadata is used, and ambiguous text resolves to `unknown`. Taxonomy in [docs/PURPOSE_TAXONOMY.md](docs/PURPOSE_TAXONOMY.md).

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

Coverage maps to OWASP MCP classes MCP01, MCP02, MCP03, MCP05, MCP07, MCP09, MCP10. MCP04 (supply chain), MCP06 (tool shadowing), and MCP08 (audit/logging) are out of scope for this alpha. MCP-002 runs only with `--baseline`/`scan-config --baseline-dir`. MCP-050 is an offline heuristic against a curated static seed list, not registry monitoring.

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
