from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mcpscan.capabilities import Capability
from mcpscan.tiers import EvidenceTier


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


class TargetOrigin(str, Enum):
    """How mcpscan came to be pointed at this target.

    CLI means the operator typed it on the command line. CONFIG means it was read out
    of an MCP client config file. The strings can be identical; the provenance is not.
    Install snippets are routinely copy-pasted from server-authored documentation, so a
    config command line can be server-influenced input wearing operator clothes.
    """

    CLI = "cli"
    CONFIG = "config"

    # NOTE: ScanTarget.origin defaults to CONFIG, the *less* trusted of the two, and
    # target.resolve_target stamps CLI explicitly. A construction site that forgets to
    # stamp an origin therefore loses downgrade authority rather than gaining it.
    # Defaulting to CLI would have been fail-open on a trust boundary.


class PurposeSource(str, Enum):
    """Where a purpose came from, which decides how far it may be trusted.

    Operator-supplied (may downgrade):
      FLAG        --purpose / --purpose-category, typed by the operator.
      INVOCATION  the command line or URL the operator typed. A server cannot forge it.

    Not operator-supplied (may never downgrade):
      CONFIG      a command line or URL read from an MCP client config file. Reads as
                  operator intent but may have been copy-pasted from the server's own
                  install instructions.
      SERVER_INFO the server describing itself. Straightforwardly attacker-controlled.
    """

    FLAG = "flag"
    INVOCATION = "invocation"
    CONFIG = "config"
    SERVER_INFO = "server_info"
    UNKNOWN = "unknown"


class ContextualVerdict(str, Enum):
    EXPECTED_BY_PURPOSE = "expected_by_purpose"
    EXPECTED_UNCONFIRMED = "expected_unconfirmed"
    UNEXPECTED = "unexpected"
    UNDECLARED = "undeclared"
    UNADJUDICATED = "unadjudicated"


class ScanTarget(BaseModel):
    raw: str | None = None
    kind: TargetKind
    transport: Transport
    origin: TargetOrigin = TargetOrigin.CONFIG
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
    #: What this scan was able to look at. Checks are selected against it and
    #: every report states it.
    tier: EvidenceTier = EvidenceTier.LIVE
    target: ScanTarget
    server: ServerInfo = Field(default_factory=ServerInfo)
    tools: list[ExposedTool] = Field(default_factory=list)
    resources: list[ExposedResource] = Field(default_factory=list)
    prompts: list[ExposedPrompt] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    unauthenticated_enumeration: bool = False


class FindingScope(str, Enum):
    """What a finding is about, which decides whether purpose can adjudicate it.

    SURFACE findings are about capabilities the server exposes — a tool that
    reads files. "Does this server need that?" is a sensible question, and the
    adjudicator answers it against the declared purpose.

    CONFIGURATION findings are about how the server is launched — an unpinned
    package, a credential in the environment, the whole home directory passed
    as an argument. Purpose cannot make any of those appropriate. Adjudicating
    them produces nonsense in both directions: escalated as a "possible hidden
    capability" because no purpose lists "unpinned package" as expected, or
    downgraded to INFO because a filesystem server is of course expected to
    read files — which would quietly excuse handing it every file you own.
    """

    SURFACE = "surface"
    CONFIGURATION = "configuration"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    original_severity: Severity | None = None
    adjusted_severity: Severity | None = None
    contextual_verdict: ContextualVerdict = ContextualVerdict.UNADJUDICATED
    verdict_reasoning: str = ""
    capability: Capability
    scope: FindingScope = FindingScope.SURFACE
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


class LaunchSurface(BaseModel):
    """How the server is started, as part of the surface being watched.

    Without this, a rug pull that leaves every tool description byte-identical
    and changes `uvx thing` to `uvx thing --exfil` produces no drift at all.
    The tool surface is what the server SAYS; the launch is what actually runs,
    and an attacker who can edit a config can change the second without
    touching the first.

    Environment variable NAMES only. A changed value is invisible here by
    design — values are the operator's own secrets, and a hash of one is a
    verification oracle for guessing it.
    """

    command_sha256: str | None = None
    args_sha256: str | None = None
    #: Kept in clear: an argument list is not a secret and naming what changed
    #: is the entire value of a drift report.
    argv_preview: list[str] = Field(default_factory=list)
    env_names: list[str] = Field(default_factory=list)
    transport: str | None = None
    url: str | None = None


class SurfaceSnapshot(BaseModel):
    surface_version: int = 2
    tools: list[SurfaceItem] = Field(default_factory=list)
    resources: list[SurfaceItem] = Field(default_factory=list)
    prompts: list[SurfaceItem] = Field(default_factory=list)
    launch: LaunchSurface = Field(default_factory=LaunchSurface)


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
    tier: EvidenceTier = EvidenceTier.LIVE
    #: Checks the tier could not supply inputs for. Reported, never silent.
    checks_not_run: list[dict[str, str]] = Field(default_factory=list)
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
    #: None when zero servers were successfully scanned. A grade asserts that something
    #: was assessed; printing one over an empty result set is a false clean bill of
    #: health. See BRIEF-0.1.1.md bug 2b.
    worst_grade: str | None = None


class ConfigScanResult(BaseModel):
    config_paths: list[str] = Field(default_factory=list)
    server_results: list[ConfigServerResult] = Field(default_factory=list)
    failures: list[ConfigServerFailure] = Field(default_factory=list)
    skipped: list[SkippedConfiguredServer] = Field(default_factory=list)
    summary: ConfigScanSummary
