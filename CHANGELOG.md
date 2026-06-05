# Changelog

## v0.1.0-alpha.1 - Unreleased

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
