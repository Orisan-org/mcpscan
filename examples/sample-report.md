# mcpscan report

## Summary
- Target: .venv/bin/python tests/fixtures/malicious_server.py
- Server: githab
- Transport: stdio
- Grade: F
- Critical: 1
- High: 6
- Medium: 1
- Low: 0

## Findings

### MCP-020 - Secret exposure in metadata
Severity: Critical  
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
Target: search  
Payload stored: false  

Evidence:
Description for tool 'search' contains instruction-like phrase 'ignore previous instructions'.

Remediation:
Remove embedded instructions from MCP metadata and treat descriptions as untrusted display text.

Reference:
OWASP MCP Top 10: Tool poisoning

### MCP-010 - Dangerous capability exposure
Severity: High  
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
Target: env_file  
Payload stored: false  

Evidence:
Resource 'file://.env/' appears to expose sensitive data or file signal '.env'.

Remediation:
Remove sensitive resources from MCP exposure or gate them behind explicit authorization.

Reference:
OWASP MCP Top 10: Data exposure

### MCP-021 - Sensitive data or file exposure
Severity: High  
Target: search  
Payload stored: false  

Evidence:
Tool 'search' appears to expose sensitive data or file signal '.env'.

Remediation:
Restrict access to sensitive files and avoid exposing PII or secrets through MCP tools.

Reference:
OWASP MCP Top 10: Data exposure

### MCP-030 - Command or code injection surface
Severity: High  
Target: run_command  
Payload stored: false  

Evidence:
Tool 'run_command' accepts unconstrained string parameter 'command' and appears to execute commands, code, or queries.

Remediation:
Constrain executable inputs with enums, patterns, length limits, allowlists, and server-side validation.

Reference:
OWASP MCP Top 10: Injection

### MCP-050 - Lookalike or typosquat name
Severity: Medium  
Target: githab  
Payload stored: false  

Evidence:
Name 'githab' is visually similar to known MCP server name 'github'.

Remediation:
Verify package provenance, repository ownership, and installation source before trusting this server.

Reference:
OWASP MCP Top 10: Supply chain
