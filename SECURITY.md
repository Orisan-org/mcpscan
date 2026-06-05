# Security Policy

## Supported Versions

`mcpscan` is currently an alpha project. Security fixes are handled on the latest `main` branch until tagged releases begin.

## Reporting A Vulnerability

Please report security issues privately to the project owner before public disclosure. Include:

- affected version or commit
- target transport (`stdio`, Streamable HTTP, or SSE)
- minimal reproduction steps
- expected versus actual behavior
- whether any sensitive data may have been exposed

## Privacy Boundary

`mcpscan` is a local scanner. It should not upload source code, prompts, secrets, raw MCP responses, or findings to any external service.

Findings should contain redacted evidence only and must keep `payload_stored=false`.
