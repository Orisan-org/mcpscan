from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mcpscan.capabilities import Capability


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Transport(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


class TargetKind(str, Enum):
    COMMAND = "command"
    URL = "url"


class PurposeCategory(str, Enum):
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    SHELL_EXECUTION = "shell_execution"
    CODE_EXECUTION = "code_execution"
    BROWSER_AUTOMATION = "browser_automation"
    API_WRAPPER = "api_wrapper"
    WEB_SEARCH = "web_search"
    COMMUNICATION = "communication"
    DEV_TOOLS = "dev_tools"
    MEMORY_STORE = "memory_store"
    UNKNOWN = "unknown"


class PurposeSource(str, Enum):
    FLAG = "flag"
    SERVER_INFO = "server_info"
    UNKNOWN = "unknown"


class ContextualVerdict(str, Enum):
    EXPECTED_BY_PURPOSE = "expected_by_purpose"
    UNEXPECTED = "unexpected"
    UNDECLARED = "undeclared"
    UNADJUDICATED = "unadjudicated"


class ScanTarget(BaseModel):
    raw: str | None = None
    kind: TargetKind
    transport: Transport
    command: list[str] | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    env: dict[str, str] = Field(default_factory=dict, exclude=True)


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    instructions: str | None = None
    protocol_version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)


class ExposedTool(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class ExposedResource(BaseModel):
    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class ExposedPrompt(BaseModel):
    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ScanContext(BaseModel):
    target: ScanTarget
    server: ServerInfo = Field(default_factory=ServerInfo)
    tools: list[ExposedTool] = Field(default_factory=list)
    resources: list[ExposedResource] = Field(default_factory=list)
    prompts: list[ExposedPrompt] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    unauthenticated_enumeration: bool = False


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    original_severity: Severity | None = None
    adjusted_severity: Severity | None = None
    contextual_verdict: ContextualVerdict = ContextualVerdict.UNADJUDICATED
    verdict_reasoning: str = ""
    capability: Capability
    owasp_mcp: str
    target: str
    evidence: str
    remediation: str
    reference: str
    payload_stored: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SurfaceItem(BaseModel):
    name: str
    description_sha256: str | None = None
    schema_sha256: str | None = None


class SurfaceSnapshot(BaseModel):
    surface_version: int = 1
    tools: list[SurfaceItem] = Field(default_factory=list)
    resources: list[SurfaceItem] = Field(default_factory=list)
    prompts: list[SurfaceItem] = Field(default_factory=list)


class PurposeProfile(BaseModel):
    category: PurposeCategory = PurposeCategory.UNKNOWN
    category_source: PurposeSource = PurposeSource.UNKNOWN
    declared_text: str = ""
    expected_capabilities: list[Capability] = Field(default_factory=list)


class ScanMetadata(BaseModel):
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0).isoformat()
    )
    timeout_seconds: float | None = None
    reproduce_command: str | None = None


class ScanResult(BaseModel):
    target: ScanTarget
    server: ServerInfo
    findings: list[Finding]
    counts: dict[str, int]
    grade: str
    surface: SurfaceSnapshot
    purpose_profile: PurposeProfile
    scan: ScanMetadata = Field(default_factory=ScanMetadata)
    warnings: list[str] = Field(default_factory=list)


class ConfiguredServer(BaseModel):
    name: str
    source_path: str
    transport: Transport
    command: list[str] | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict, exclude=True)
    env: dict[str, str] = Field(default_factory=dict, exclude=True)
    env_names: list[str] = Field(default_factory=list)


class SkippedConfiguredServer(BaseModel):
    name: str
    source_path: str
    reason: str
    env_names: list[str] = Field(default_factory=list)


class ConfigServerResult(BaseModel):
    name: str
    source_path: str
    transport: Transport
    env_names: list[str] = Field(default_factory=list)
    result: ScanResult


class ConfigServerFailure(BaseModel):
    name: str
    source_path: str
    transport: Transport | None = None
    error: str
    env_names: list[str] = Field(default_factory=list)


class ConfigScanSummary(BaseModel):
    configs_found: int
    servers_total: int
    servers_scanned: int
    servers_failed: int
    servers_skipped: int
    findings_total: int
    worst_grade: str


class ConfigScanResult(BaseModel):
    config_paths: list[str] = Field(default_factory=list)
    server_results: list[ConfigServerResult] = Field(default_factory=list)
    failures: list[ConfigServerFailure] = Field(default_factory=list)
    skipped: list[SkippedConfiguredServer] = Field(default_factory=list)
    summary: ConfigScanSummary
