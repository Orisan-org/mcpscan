from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_EGRESS = "network_egress"
    SHELL_EXEC = "shell_exec"
    CODE_EVAL = "code_eval"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXPOSURE = "data_exposure"
    PROMPT_ANOMALY = "prompt_anomaly"
    TRANSPORT_SECURITY = "transport_security"
    IDENTITY_SPOOF = "identity_spoof"
    SURFACE_DRIFT = "surface_drift"
    OTHER = "other"


OWASP_MCP_REFERENCES: dict[str, str] = {
    "MCP01": "OWASP MCP Top 10: Credential exposure",
    "MCP02": "OWASP MCP Top 10: Excessive permissions",
    "MCP03": "OWASP MCP Top 10: Tool poisoning and rug pull attacks",
    "MCP04": "OWASP MCP Top 10: Supply chain risk",
    "MCP05": "OWASP MCP Top 10: Tool invocation injection",
    "MCP06": "OWASP MCP Top 10: Tool shadowing",
    "MCP07": "OWASP MCP Top 10: Insecure transport and authentication",
    "MCP08": "OWASP MCP Top 10: Audit and logging gaps",
    "MCP09": "OWASP MCP Top 10: Identity and package spoofing",
    "MCP10": "OWASP MCP Top 10: Sensitive data exposure",
}


def owasp_reference(owasp_mcp: str) -> str:
    return OWASP_MCP_REFERENCES.get(owasp_mcp, "OWASP MCP Top 10")
