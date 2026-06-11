# mcpscan

`mcpscan` is an alpha, local-first security scanner for Model Context Protocol servers.

It connects to an MCP server over stdio or tested Streamable HTTP, enumerates exposed tools/resources/prompts/metadata, runs deterministic checks, and emits terminal, JSON, or Markdown findings before an AI agent trusts that server.

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

## Write JSON Or Markdown Reports

```bash
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output json --out /tmp/mcpscan-report.json
mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output md --out /tmp/mcpscan-report.md
```

The malicious fixture intentionally returns findings, so these commands exit `1` when findings meet the default severity threshold.

## What mcpscan Checks

| ID | Title | Severity | Capability | OWASP MCP | Status |
| --- | --- | --- | --- | --- | --- |
| MCP-001 | Tool description prompt injection | high | prompt_anomaly | MCP03 | active |
| MCP-002 | Tool definition drift | high | surface_drift | MCP03 | deferred |
| MCP-010 | Dangerous capability exposure | high | per finding | MCP02 | active |
| MCP-020 | Secret exposure in metadata | critical | credential_access | MCP01 | active |
| MCP-021 | Sensitive data or file exposure | high | data_exposure | MCP10 | active |
| MCP-030 | Command or code injection surface | high | shell_exec/code_eval | MCP05 | active |
| MCP-040 | Unauthenticated remote server | high | transport_security | MCP07 | active |
| MCP-041 | Missing TLS | high | transport_security | MCP07 | active |
| MCP-050 | Static known-name lookalike check using a curated seed list | medium | identity_spoof | MCP09 | active |

Current coverage maps to OWASP MCP classes MCP01, MCP02, MCP03, MCP05, MCP07, MCP09, and MCP10. MCP04 supply chain analysis, MCP06 intent/flow issues, and MCP08 audit/telemetry gaps are out of scope for this alpha.

MCP-002 baseline drift is deferred. MCP-050 is an offline heuristic that compares exposed server/tool names against a curated static seed list of common MCP server names. It does not monitor package registries and should not be treated as exhaustive ecosystem coverage.

## What Findings Look Like

Each finding includes:

- stable check ID
- title
- severity
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

Dynamic probing, MCP-002 tool definition drift, HTML reports, registry monitoring, GitHub Action packaging, SaaS dashboards, and runtime enforcement are not part of this alpha release.

Local MCP config/path scanning is not supported yet. To scan stdio MCP servers, pass the server launch command with `--command`; to scan remote MCP servers, pass an `http(s)` URL.

## Development And Verification

Run the local quality gates:

```bash
ruff format --check .
ruff check .
pytest
python -m mcpscan --help
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
