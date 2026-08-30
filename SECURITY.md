# Security Policy

## Scope

This policy covers the `mcpscan` codebase in this repository, published as
`orisan-mcpscan` on PyPI. It does not cover other Orisan-org repositories
(each publishes its own `SECURITY.md`), and it does not cover the security
grade a scan reports about a *target* MCP server — that's the product's
output, not a vulnerability in mcpscan itself.

## Supported Versions

`mcpscan` is currently an alpha project. Security fixes are handled on latest
`main` and current alpha tags. If a fix affects a released alpha, the release
notes will call it out.

## Reporting A Vulnerability

Please report security issues privately to the project owner before public
disclosure. **Do not open a public GitHub issue for a vulnerability.**

- **Contact:** team@orisan.org — published on orisan.org's contact page and
  site footer.
- **Please include:**
  - affected version or commit
  - target transport (`stdio`, Streamable HTTP, or SSE)
  - minimal reproduction steps
  - expected versus actual behavior
  - whether any sensitive data may have been exposed

## Response Time

We aim to acknowledge new reports within **5 business days** of receipt.
*(Proposed default — confirm or adjust before merging.)*

## Disclosure Window

We ask for **90 days** from acknowledgment before public disclosure, to allow
time to validate, fix, and release. We're willing to negotiate a shorter or
longer window with the reporter depending on severity and complexity.
*(Proposed default — confirm or adjust before merging.)*

## Privacy Boundary

`mcpscan` is a local scanner. It should not upload source code, prompts,
secrets, raw MCP responses, or findings to any external service. Remote scans
should only contact the user-provided MCP endpoint.

Findings should contain redacted evidence only and must keep
`payload_stored=false`.
