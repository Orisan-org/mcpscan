# mcpscan report

## Identity & Provenance
- Target: .venv/bin/python tests/fixtures/malicious_server.py
- Server: githab
- Server version: 1.27.2
- Transport: stdio
- Scanner: mcpscan 0.1.0
- Checks version: 1
- Timestamp UTC: 2026-06-11T18:01:53+00:00
- Reproduce command: `mcpscan scan --command '.venv/bin/python tests/fixtures/malicious_server.py' --timeout 90.0`
- Payload stored: false for all findings

## Verdict Summary
- Recommendation: do_not_connect
- Grade: F
- Purpose: unknown
- Purpose source: unknown
- Expected capabilities: none
- Critical: 1
- High: 6
- Medium: 1
- Low: 0
- Info: 0

Top findings:
- CRITICAL MCP-020 on send_report: Potential GitHub token found in tool metadata for 'send_report' at input_schema.properties.api_key.default and was redacted (ghp_...3456).
- HIGH MCP-001 on search: Description for tool 'search' contains instruction-like phrase 'ignore previous instructions'.
- HIGH MCP-010 on run_command: Tool 'run_command' appears to expose shell execution based on name, description, or schema.

## Findings

| Adjusted severity | Verdict | Capability | OWASP | Check | Target | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| critical | unadjudicated | credential_access | MCP01 | MCP-020 | send_report | Potential GitHub token found in tool metadata for 'send_report' at input_schema.properties.api_key.default and was redacted (ghp_...3456). |
| high | unadjudicated | prompt_anomaly | MCP03 | MCP-001 | search | Description for tool 'search' contains instruction-like phrase 'ignore previous instructions'. |
| high | unadjudicated | shell_exec | MCP02 | MCP-010 | run_command | Tool 'run_command' appears to expose shell execution based on name, description, or schema. |
| high | unadjudicated | credential_access | MCP02 | MCP-010 | send_report | Tool 'send_report' appears to expose credential access based on name, description, or schema. |
| high | unadjudicated | data_exposure | MCP10 | MCP-021 | env_file | Resource 'file://.env/' appears to expose sensitive data or file signal '.env'. |
| high | unadjudicated | data_exposure | MCP10 | MCP-021 | search | Tool 'search' appears to expose sensitive data or file signal '.env'. |
| high | unadjudicated | shell_exec | MCP05 | MCP-030 | run_command | Tool 'run_command' accepts unconstrained string parameter 'command' and appears to execute commands or code. |
| medium | unadjudicated | identity_spoof | MCP09 | MCP-050 | githab | Name 'githab' is visually similar to known MCP server name 'github'. |

### MCP-020 - Secret exposure in metadata
Adjusted severity: Critical
Verdict: unadjudicated
Capability: credential_access
OWASP MCP: MCP01
Target: send_report
Payload stored: false

Evidence:
Potential GitHub token found in tool metadata for 'send_report' at input_schema.properties.api_key.default and was redacted (ghp_...3456).

Remediation:
Remove secrets from MCP metadata and pass credentials through secure runtime configuration.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Credential exposure

### MCP-001 - Tool description prompt injection
Adjusted severity: High
Verdict: unadjudicated
Capability: prompt_anomaly
OWASP MCP: MCP03
Target: search
Payload stored: false

Evidence:
Description for tool 'search' contains instruction-like phrase 'ignore previous instructions'.

Remediation:
Remove embedded instructions from MCP metadata and treat descriptions as untrusted display text.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Tool poisoning and rug pull attacks

### MCP-010 - Dangerous capability exposure
Adjusted severity: High
Verdict: unadjudicated
Capability: shell_exec
OWASP MCP: MCP02
Target: run_command
Payload stored: false

Evidence:
Tool 'run_command' appears to expose shell execution based on name, description, or schema.

Remediation:
Restrict dangerous tools, require explicit approval, and scope parameters as narrowly as possible.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Excessive permissions

### MCP-010 - Dangerous capability exposure
Adjusted severity: High
Verdict: unadjudicated
Capability: credential_access
OWASP MCP: MCP02
Target: send_report
Payload stored: false

Evidence:
Tool 'send_report' appears to expose credential access based on name, description, or schema.

Remediation:
Restrict dangerous tools, require explicit approval, and scope parameters as narrowly as possible.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Excessive permissions

### MCP-021 - Sensitive data or file exposure
Adjusted severity: High
Verdict: unadjudicated
Capability: data_exposure
OWASP MCP: MCP10
Target: env_file
Payload stored: false

Evidence:
Resource 'file://.env/' appears to expose sensitive data or file signal '.env'.

Remediation:
Remove sensitive resources from MCP exposure or gate them behind explicit authorization.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Sensitive data exposure

### MCP-021 - Sensitive data or file exposure
Adjusted severity: High
Verdict: unadjudicated
Capability: data_exposure
OWASP MCP: MCP10
Target: search
Payload stored: false

Evidence:
Tool 'search' appears to expose sensitive data or file signal '.env'.

Remediation:
Restrict access to sensitive files and avoid exposing PII or secrets through MCP tools.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Sensitive data exposure

### MCP-030 - Command or code injection surface
Adjusted severity: High
Verdict: unadjudicated
Capability: shell_exec
OWASP MCP: MCP05
Target: run_command
Payload stored: false

Evidence:
Tool 'run_command' accepts unconstrained string parameter 'command' and appears to execute commands or code.

Remediation:
Constrain executable inputs with enums, patterns, length limits, allowlists, and server-side validation.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Tool invocation injection

### MCP-050 - Static known-name lookalike check
Adjusted severity: Medium
Verdict: unadjudicated
Capability: identity_spoof
OWASP MCP: MCP09
Target: githab
Payload stored: false

Evidence:
Name 'githab' is visually similar to known MCP server name 'github'.

Remediation:
Verify package provenance, repository ownership, and installation source before trusting this server.

Verdict reasoning:
No declared purpose available; pass --purpose or --purpose-category to enable contextual adjudication.

Reference:
OWASP MCP Top 10: Identity and package spoofing

## What We Did Not Check
- Server source code is not analyzed
- Runtime behavior is not observed
- Dependencies/supply chain are not audited
- Drift requires --baseline rescans
- Registry squatting coverage limited to a curated seed list

## Reproduce
`mcpscan scan --command '.venv/bin/python tests/fixtures/malicious_server.py' --timeout 90.0`
