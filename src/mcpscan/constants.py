SCANNER_NAME = "mcpscan"
REPORT_VERSION = "2.0"
CHECKS_VERSION = "1"
NOT_CHECKED = [
    "Server source code is not analyzed",
    "OWASP MCP04 (supply chain), MCP06 (tool shadowing) and MCP08 (audit/logging) have no check",
    "Runtime behavior is not observed",
    "Dependencies/supply chain are not audited",
    "Drift requires --baseline rescans",
    "Registry squatting coverage limited to a curated seed list",
]
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ENUMERATION = 3
EXIT_INTERNAL = 4
