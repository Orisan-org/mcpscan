# Validation Results

This file tracks sanitized field-validation notes for real MCP servers. It is for repeatable product validation, not for storing raw MCP responses, prompt payloads, source code, credentials, or private target data.

Do not commit raw scan responses. Summarize findings with check IDs, redacted evidence, and reviewer judgment only.

## Results Table

| Target name | Target type | Install command or source | Scan command | Scan date | Result grade | Finding IDs | True positives | Suspected false positives | Suspected false negatives | Confusing output | Crash/error behavior | README/docs improvement | Raw payload stored? | `payload_stored=false` verified? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _Template_ | stdio / Streamable HTTP / SSE | Redacted install/source note | Redacted command with no secrets | YYYY-MM-DD | A-F | MCP-001, MCP-010 | Brief sanitized note | Brief sanitized note | Brief sanitized note | Brief sanitized note | None / summarized error | Brief improvement | No | Yes |
| memory MCP server | stdio | npm package via `npx`; clean validation venv | `mcpscan scan --command "npx -y @modelcontextprotocol/server-memory"` | 2026-06-06 | A | None | None | Previous MCP-030 false positive on `search_nodes(query)` is fixed | None observed | Stale global `mcpscan` initially caused confusion after editable install failed | Document stale/global install troubleshooting | No | Yes |
| filesystem MCP server | stdio | npm package via `npx`; safe temp root only | `mcpscan scan --command "npx -y @modelcontextprotocol/server-filesystem <safe-temp-root>"` | 2026-06-06 | D | MCP-010 | File capability exposure findings on read/write/info tools were true positives | None observed | None observed | None after clean venv install | Document safe-root validation and binary verification | No | Yes |
| fetch MCP server via npm package guess | stdio | npm package guess via `npx` | `mcpscan scan --command "npx -y @modelcontextprotocol/server-fetch"` | 2026-06-06 | No report | None | None | None | None | Target command failed before MCP enumeration; scanner showed generic TaskGroup enumeration error | Improve stdio startup/package-failure errors | No report generated | No report generated |
| fetch MCP server via PyPI package | stdio | Python package via `uvx` | `mcpscan scan --command "uvx mcp-server-fetch"` | 2026-06-06 | D | MCP-010 | Network fetch capability with URL input was flagged after MCP-010 tuning | None observed | None observed in rerun | None | No MCP-030/MCP-021 observed; MCP-010 false negative fixed | No | Yes |

## Sanitized Validation Notes

### memory MCP server

- Target type: stdio
- Install command or source: npm package via `npx`
- Scan command: `mcpscan scan --command "npx -y @modelcontextprotocol/server-memory"`
- Scan date: 2026-06-06
- Result grade: A
- Finding IDs: none
- True positives: none
- Suspected false positives: none after MCP-030 execution-semantics fix
- Suspected false negatives: none observed during this pass
- Confusing output: stale global `mcpscan` was used after editable install failed to fetch build dependencies; clean venv fixed this
- Crash/error behavior: none after clean install
- README/docs improvement: add stale/global install troubleshooting to validation protocol
- Raw payload stored: No
- `payload_stored=false` verified: Yes
- Sanitization notes: no raw MCP responses, prompt payloads, source code, credentials, or secrets committed

### filesystem MCP server

- Target type: stdio
- Install command or source: npm package via `npx`, pointed only at a safe temporary root
- Scan command: `mcpscan scan --command "npx -y @modelcontextprotocol/server-filesystem <safe-temp-root>"`
- Scan date: 2026-06-06
- Result grade: D
- Finding IDs: MCP-010
- True positives: five file capability exposure findings on file read/write/info-style tools
- Suspected false positives: none observed during this pass
- Suspected false negatives: none observed during this pass
- Confusing output: none after clean venv install
- Crash/error behavior: none after clean venv install
- README/docs improvement: remind validators to verify the active `mcpscan` binary
- Raw payload stored: No
- `payload_stored=false` verified: Yes
- Sanitization notes: no raw MCP responses, prompt payloads, source code, credentials, or secrets committed

### fetch MCP server via npm package guess

- Target type: stdio
- Install command or source: npm package guess via `npx`
- Scan command: `mcpscan scan --command "npx -y @modelcontextprotocol/server-fetch"`
- Scan date: 2026-06-06
- Result grade: no report generated
- Finding IDs: none
- True positives: none
- Suspected false positives: none
- Suspected false negatives: not applicable; target failed before MCP enumeration
- Confusing output: scanner surfaced a generic TaskGroup enumeration error instead of the package/root-cause failure
- Crash/error behavior: target command failed with npm package not found before MCP enumeration
- README/docs improvement: record package/path mismatch and stale/global install checks in validation workflow
- Raw payload stored: No report generated
- `payload_stored=false` verified: No report generated
- Sanitization notes: no raw MCP responses, prompt payloads, source code, credentials, or secrets committed
- Product action: improve stdio connector/CLI error ergonomics for command startup and package failures

### fetch MCP server via PyPI package

- Target type: stdio
- Install command or source: Python package via `uvx`
- Scan command: `mcpscan scan --command "uvx mcp-server-fetch"`
- Scan date: 2026-06-06
- Result grade: D
- Finding IDs: MCP-010
- True positives: outbound network fetch capability with URL input
- Suspected false positives: none observed
- Suspected false negatives: none observed in rerun after MCP-010 tuning
- Confusing output: none
- Crash/error behavior: none
- README/docs improvement: keep this as a regression validation target for MCP-010 network egress
- Raw payload stored: No
- `payload_stored=false` verified: Yes
- Sanitization notes: no raw MCP responses, prompt payloads, source code, credentials, or secrets committed
- Product action: fixed MCP-010 false negative for fetch/url network egress without adding runtime registry monitoring or external calls

## Entry Template

Copy this block for longer notes when a table row is too small.

```md
### Target: <name>

- Target type: stdio / Streamable HTTP / SSE
- Install command or source: <redacted, no secrets>
- Scan command: <redacted, no secrets>
- Scan date: YYYY-MM-DD
- Result grade: A / B / C / D / F
- Finding IDs: MCP-...
- True positives:
  - <sanitized finding judgment>
- Suspected false positives:
  - <sanitized reason>
- Suspected false negatives:
  - <sanitized missing-risk note>
- Confusing output:
  - <what was unclear>
- Crash/error behavior:
  - <none, or sanitized error summary>
- README/docs improvement:
  - <one improvement suggested by this run>
- Raw payload stored: No
- payload_stored=false verified: Yes / No
- Sanitization notes:
  - <confirm no raw MCP responses, prompt payloads, source code, credentials, or secrets were committed>
```

## Sanitization Rules

- Do not paste raw tool descriptions, prompt content, resource bodies, source code, server responses, headers, tokens, credentials, or customer data.
- Keep scan commands free of real secrets. Replace sensitive values with `<redacted>`.
- Prefer finding IDs and short reviewer judgment over long evidence excerpts.
- Confirm every committed result says raw payload stored: `No`.
- Confirm every committed JSON-derived note was checked for `payload_stored=false`.
