# mcpscan

`mcpscan` is an alpha, local-first security scanner for Model Context Protocol servers.

It connects to an MCP server over stdio or tested Streamable HTTP, enumerates exposed tools/resources/prompts/metadata, runs deterministic checks, and emits terminal, JSON, or Markdown findings before an AI agent trusts that server.

## Install and run in one line

Run `mcpscan` without cloning, in a throwaway environment, with [uvx](https://docs.astral.sh/uv/) (or `pipx run`):

```bash
uvx --from git+https://github.com/Orisan-org/mcpscan mcpscan scan --command "npx -y @modelcontextprotocol/server-everything"
```

`uvx` fetches mcpscan into an isolated environment and runs it in one step; swap `--command` for the MCP server you want to scan. The pipx equivalent is `pipx run --spec git+https://github.com/Orisan-org/mcpscan mcpscan --help`.

## 60-Second Quickstart

From a cloned repo:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
mcpscan list-checks
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py"
```

Use `python -m venv .venv` instead if your system exposes Python 3 as `python`. Editable install may need network access to fetch build dependencies such as `hatchling`.

The benign fixture should return grade `A` with no findings.

## Scan Your Client Configs

Use `scan-config` when a review starts from an MCP client config instead of a single server command:

```bash
mcpscan scan-config ./mcp.json --yes
mcpscan scan-config ./.mcp.json --yes --output json --out /tmp/mcpscan-config-report.json
mcpscan scan-config ./.mcp.json --yes --push-envelope --control-plane-url http://127.0.0.1:8787
```

Supported config shape:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/mcpscan-safe-root"]
    },
    "remote-dev": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

`scan-config` scans explicit config paths and can also discover known local MCP config locations for Claude Desktop, Claude Code, Cursor, and Windsurf. Stdio entries prompt before local execution unless `--yes` is provided. Remote URL entries do not prompt because they do not execute local commands.

Environment values from config files are passed to stdio servers but are redacted from all output. Reports show env names/counts only.

Use `--push-envelope` to POST the shared Orisan envelope directly to the control plane. The control-plane URL defaults to `ORISAN_CONTROL_PLANE_URL` or `http://127.0.0.1:8787`; pass `--ingest-token` or set `ORISAN_INGEST_TOKEN` when the ingest endpoint requires bearer auth.

## Scan A Stdio MCP Server

Stdio scans launch the command you provide, perform the MCP handshake, enumerate the server, and then run checks over the exposed definitions.

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py"
```

Important: stdio targets execute locally. Only scan commands you are willing to run on your machine.

Cold-start `npx` or `uvx` servers can take 30+ seconds on first run. The default timeout is 90 seconds; use `--timeout` if your target needs more or less time.

## Scan A Streamable HTTP MCP Server

Streamable HTTP is the primary tested remote transport in this release. This local fixture starts an MCP server on `127.0.0.1:8000`.

Terminal 1:

```bash
.venv/bin/python tests/fixtures/remote_streamable_server.py --port 8000
```

Terminal 2:

```bash
mcpscan scan http://127.0.0.1:8000/mcp --transport http
```

Remote scans do not contact external services except the MCP server URL you provide. SSE is wired through the official MCP SDK when available, but it is not integration-tested in this release.

## Write JSON, Markdown, Or SARIF Reports

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output json --out /tmp/mcpscan-report.json
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output md --out /tmp/mcpscan-report.md
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output sarif --out /tmp/mcpscan-report.sarif
```

The malicious fixture intentionally returns findings, so these commands exit `1` when findings meet the default severity threshold.

For GitHub code scanning upload, see [docs/CI.md](docs/CI.md).

## Purpose Profiles

Reports include a deterministic purpose profile describing what the MCP server claims to be. You can provide it explicitly:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py" --purpose-category filesystem
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py" --purpose "filesystem server for reading and writing files"
```

If no purpose flag is provided, `mcpscan` uses server metadata such as name and instructions when available. Ambiguous or empty text resolves to `unknown`.

Purpose profiles feed deterministic contextual verdicts and adjusted severities. The static taxonomy is documented in [docs/PURPOSE_TAXONOMY.md](docs/PURPOSE_TAXONOMY.md).

## Context-Aware Verdicts

`mcpscan` does not suppress findings. It labels each finding with a contextual verdict and keeps both original and adjusted severity when they differ.

Verdicts are deterministic:

- `expected_by_purpose`: the capability is inherent to the declared purpose and the check is downgrade-eligible.
- `unexpected`: the capability is outside the purpose category, but the declared text mentions it.
- `undeclared`: the capability is outside the purpose category and not mentioned in declared text.
- `unadjudicated`: no declared purpose was available.

Demo: expected filesystem access is reported for completeness:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/purpose_filesystem_server.py" --purpose-category filesystem --no-color
```

Expected output includes:

```text
INFO (was HIGH)  expected_by_purpose  MCP-010  read_file
```

Demo: hidden file access in a weather server is escalated:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/purpose_weather_file_server.py" --purpose "weather server" --no-color
```

Expected output includes:

```text
CRITICAL (was HIGH)  undeclared  MCP-010  read_file
```

Demo: declared URL fetching is still reported, but not escalated:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/purpose_weather_fetch_server.py" --purpose "weather server that can fetch URLs" --no-color
```

Expected output includes:

```text
HIGH  unexpected  MCP-010  fetch
```

## What mcpscan Checks

| ID | Title | Severity | Capability | OWASP MCP | Status |
| --- | --- | --- | --- | --- | --- |
| MCP-001 | Tool description prompt injection | high | prompt_anomaly | MCP03 | active |
| MCP-002 | Tool definition drift | high | surface_drift | MCP03 | active with `--baseline` |
| MCP-010 | Dangerous capability exposure | high | per finding | MCP02 | active |
| MCP-020 | Secret exposure in metadata | critical | credential_access | MCP01 | active |
| MCP-021 | Sensitive data or file exposure | high | data_exposure | MCP10 | active |
| MCP-030 | Command or code injection surface | high | shell_exec/code_eval | MCP05 | active |
| MCP-040 | Unauthenticated remote server | high | transport_security | MCP07 | active |
| MCP-041 | Missing TLS | high | transport_security | MCP07 | active |
| MCP-050 | Static known-name lookalike check using a curated seed list | medium | identity_spoof | MCP09 | active |

Current coverage maps to OWASP MCP classes MCP01, MCP02, MCP03, MCP05, MCP07, MCP09, and MCP10. MCP04 supply chain analysis, MCP06 intent/flow issues, and MCP08 audit/telemetry gaps are out of scope for this alpha.

MCP-002 runs only when you provide a previous JSON report with `--baseline` or use `scan-config --baseline-dir`. MCP-050 is an offline heuristic that compares exposed server/tool names against a curated static seed list of common MCP server names. It does not monitor package registries and should not be treated as exhaustive ecosystem coverage.

## Drift Detection

JSON reports include a `surface` block with hash-only snapshots of exposed tools, resources, and prompts. Description text is whitespace-normalized before hashing. Schemas are canonicalized with sorted JSON keys before hashing. The report does not add raw descriptions, schemas, or MCP responses to drift evidence.

Create a baseline report:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py" --output json --out /tmp/mcpscan-baseline.json
```

Compare a later scan against that baseline:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server_v2.py" --baseline /tmp/mcpscan-baseline.json
```

For explicit MCP config scanning, keep one baseline per server name:

```bash
mcpscan scan-config ./mcp.json --yes --baseline-dir /tmp/mcpscan-baselines
```

MCP-002 emits high-severity findings for added tools, removed tools, description hash changes, and schema hash changes. Evidence uses tool names and hash prefixes only.

## What Findings Look Like

Each finding includes:

- stable check ID
- title
- original severity
- adjusted severity
- contextual verdict
- verdict reasoning
- capability
- OWASP MCP Top 10 ID
- target
- redacted evidence
- remediation
- reference
- `payload_stored=false`

Example:

```json
{
  "id": "MCP-030",
  "title": "Command or code injection surface",
  "severity": "high",
  "original_severity": "high",
  "adjusted_severity": "high",
  "contextual_verdict": "unadjudicated",
  "verdict_reasoning": "No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.",
  "capability": "shell_exec",
  "owasp_mcp": "MCP05",
  "target": "run_command",
  "evidence": "Tool 'run_command' accepts unconstrained string parameter 'command' and appears to execute commands or code.",
  "remediation": "Constrain executable inputs with enums, patterns, length limits, allowlists, and server-side validation.",
  "reference": "OWASP MCP Top 10: Injection",
  "payload_stored": false
}
```

## Privacy And Evidence Model

By default, `mcpscan` runs locally. It does not upload source code, prompts, secrets, raw MCP responses, or findings to Orisan or any external service.

Findings store safe, redacted evidence only. They identify the location and class of risk without storing full raw payloads. Every finding sets `payload_stored=false`.

Do not place secrets directly in `--command`, headers, or report output paths. Reports may include user-provided target strings such as the stdio command for traceability.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and no finding met the severity threshold |
| `1` | Scan completed and at least one finding met the severity threshold |
| `2` | User input or CLI usage error |
| `3` | Connection or enumeration error |
| `4` | Internal scanner error |

Use `--severity-threshold low|medium|high|critical` to control when findings return exit `1`.

## Supported Transports

| Transport | Status |
| --- | --- |
| stdio | Tested with local fixture servers |
| Streamable HTTP | Tested with a local fixture server |
| SSE | Wired through the installed MCP SDK when available, but not integration-tested |

## Limitations And Non-Goals

`mcpscan` does not secure the model, enforce runtime policy, block agent actions, modify the target server, monitor registries, upload findings, or use LLM verdicts.

Dynamic probing, HTML reports, registry monitoring, GitHub Action packaging, SaaS dashboards, and runtime enforcement are not part of this alpha release.

`scan-config` only scans MCP config files that you explicitly pass or known local config paths it discovers. It does not scan arbitrary home-directory contents, source trees, browser profiles, or secrets stores.

## Development And Verification

Run the local quality gates:

```bash
ruff format --check .
ruff check .
pytest
python -m mcpscan --help
python -m mcpscan scan-config --help
python -m mcpscan list-checks
```

Network-dependent stdio checks are excluded from default `pytest`. To run them manually:

```bash
pytest -m network
```

Release-readiness smoke checks:

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py"
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --severity-threshold high
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output json --out /tmp/mcpscan-smoke.json || test $? -eq 1
mcpscan scan-config tests/fixtures/configs/mixed.json --yes --output json --out /tmp/mcpscan-config-smoke.json || test $? -eq 1
```

For Streamable HTTP, start the local fixture and scan it:

```bash
.venv/bin/python tests/fixtures/remote_streamable_server.py --port 8000
mcpscan scan http://127.0.0.1:8000/mcp --transport http
```

## Field Validation

After the alpha release, use [docs/VALIDATION_PROTOCOL.md](docs/VALIDATION_PROTOCOL.md) for repeatable real-world MCP server testing and record sanitized notes in [docs/VALIDATION_RESULTS.md](docs/VALIDATION_RESULTS.md). Validation notes must not include raw MCP responses, prompt payloads, source code, credentials, or secrets.

## License

MIT
