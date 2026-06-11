# mcpscan report

## Summary
- Target: .venv/bin/python tests/fixtures/malicious_server.py
- Server: githab
- Transport: stdio
- Purpose: unknown
- Purpose source: unknown
- Expected capabilities: none
- Grade: F
- Critical: 1
- High: 6
- Medium: 1
- Low: 0

## Findings

### MCP-020 - Secret exposure in metadata
Severity: Critical
Capability: credential_access
OWASP MCP: MCP01
Target: send_report
Payload stored: false

Evidence:
Potential GitHub token found in tool metadata for 'send_report' at input_schema.properties.api_key.default and was redacted (ghp_...3456).

Remediation:
Remove secrets from MCP metadata and pass credentials through secure runtime configuration.

Reference:
OWASP MCP Top 10: Credential exposure

### MCP-001 - Tool description prompt injection
Severity: High
Capability: prompt_anomaly
OWASP MCP: MCP03
Target: search
Payload stored: false

Evidence:
Description for tool 'search' contains instruction-like phrase 'ignore previous instructions'.

Remediation:
Remove embedded instructions from MCP metadata and treat descriptions as untrusted display text.

Reference:
OWASP MCP Top 10: Tool poisoning and rug pull attacks

### MCP-010 - Dangerous capability exposure
Severity: High
Capability: shell_exec
OWASP MCP: MCP02
Target: run_command
Payload stored: false

Evidence:
Tool 'run_command' appears to expose shell execution based on name, description, or schema.

Remediation:
Restrict dangerous tools, require explicit approval, and scope parameters as narrowly as possible.

Reference:
OWASP MCP Top 10: Excessive permissions

### MCP-010 - Dangerous capability exposure
Severity: High
Capability: credential_access
OWASP MCP: MCP02
Target: send_report
Payload stored: false

Evidence:
Tool 'send_report' appears to expose credential access based on name, description, or schema.

Remediation:
Restrict dangerous tools, require explicit approval, and scope parameters as narrowly as possible.

Reference:
OWASP MCP Top 10: Excessive permissions

### MCP-021 - Sensitive data or file exposure
Severity: High
Capability: data_exposure
OWASP MCP: MCP10
Target: env_file
Payload stored: false

Evidence:
Resource 'file://.env/' appears to expose sensitive data or file signal '.env'.

Remediation:
Remove sensitive resources from MCP exposure or gate them behind explicit authorization.

Reference:
OWASP MCP Top 10: Sensitive data exposure

### MCP-021 - Sensitive data or file exposure
Severity: High
Capability: data_exposure
OWASP MCP: MCP10
Target: search
Payload stored: false

Evidence:
Tool 'search' appears to expose sensitive data or file signal '.env'.

Remediation:
Restrict access to sensitive files and avoid exposing PII or secrets through MCP tools.

Reference:
OWASP MCP Top 10: Sensitive data exposure

### MCP-030 - Command or code injection surface
Severity: High
Capability: shell_exec
OWASP MCP: MCP05
Target: run_command
Payload stored: false

Evidence:
Tool 'run_command' accepts unconstrained string parameter 'command' and appears to execute commands or code.

Remediation:
Constrain executable inputs with enums, patterns, length limits, allowlists, and server-side validation.

Reference:
OWASP MCP Top 10: Tool invocation injection

### MCP-050 - Static known-name lookalike check
Severity: Medium
Capability: identity_spoof
OWASP MCP: MCP09
Target: githab
Payload stored: false

Evidence:
Name 'githab' is visually similar to known MCP server name 'github'.

Remediation:
Verify package provenance, repository ownership, and installation source before trusting this server.

Reference:
OWASP MCP Top 10: Identity and package spoofing
