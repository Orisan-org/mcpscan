# mcpscan

`mcpscan` is a local-first security scanner for Model Context Protocol servers.

It connects to an MCP server, enumerates exposed tools, resources, prompts, and server metadata, runs deterministic security checks, and produces terminal, JSON, or Markdown findings before an AI agent trusts that server.

## Why MCP security matters

MCP servers can expose tools that read files, run commands, access credentials, or send network requests. Tool descriptions and schemas are also part of the model-visible surface. `mcpscan` gives AppSec and product security teams a quick local review step before connecting agents to new MCP servers.

## Install

```bash
pipx install mcpscan
```

For local development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quickstart

```bash
mcpscan list-checks
mcpscan scan --command "python tests/fixtures/benign_server.py"
mcpscan scan --command "python tests/fixtures/malicious_server.py" --output md --out examples/sample-report.md
```

## Important: stdio targets execute locally

When scanning a stdio MCP server, `mcpscan` launches the command you provide so it can perform the MCP handshake and enumerate capabilities. Only scan commands you are willing to execute on your machine.

## What mcpscan checks

Phase 1 includes deterministic checks for prompt injection in metadata, dangerous capabilities, secret exposure, sensitive file/data exposure, command/code injection surfaces, unauthenticated remote enumeration, missing TLS, and conservative lookalike names.

## What mcpscan does not do

`mcpscan` does not secure the model, does not enforce runtime policy, does not modify the target server, does not upload source code, and does not send findings to a cloud service. It only analyzes what the target MCP server exposes over MCP.

Dynamic probing, baseline diff, HTML reports, registry monitoring, and GitHub Actions integration are deferred.

## Report formats

- `table`: Rich terminal summary and findings table
- `json`: machine-readable report
- `md`: GitHub-readable Markdown report

## Privacy

By default, `mcpscan` runs locally. It does not upload source code, server responses, prompts, secrets, or findings to Orisan or any external service. Findings store redacted evidence only and always set `payload_stored=false`.

## Check catalogue

| ID | Title | Severity | Status |
| --- | --- | --- | --- |
| MCP-001 | Tool description prompt injection | high | active |
| MCP-002 | Tool definition drift | high | deferred |
| MCP-010 | Dangerous capability exposure | high | active |
| MCP-020 | Secret exposure in metadata | critical | active |
| MCP-021 | Sensitive data or file exposure | high | active |
| MCP-030 | Command or code injection surface | high | active |
| MCP-040 | Unauthenticated remote server | high | active |
| MCP-041 | Missing TLS | high | active |
| MCP-050 | Lookalike or typosquat name | medium | active |

## Roadmap

- Phase 1: local CLI, stdio scanning, stable remote scanning, static checks, terminal/JSON/Markdown reports
- Phase 2: safe dynamic probing, baseline/diff, HTML report, additional medium checks
- Phase 3: GitHub Action, registry monitoring, hosted workflow only if validated

## Contributing

Run:

```bash
ruff format --check .
ruff check .
pytest
```

## License

MIT
