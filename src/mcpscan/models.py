from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


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


class ScanTarget(BaseModel):
    raw: str | None = None
    kind: TargetKind
    transport: Transport
    command: list[str] | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None
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
    target: str
    evidence: str
    remediation: str
    reference: str
    payload_stored: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    target: ScanTarget
    server: ServerInfo
    findings: list[Finding]
    counts: dict[str, int]
    grade: str
    warnings: list[str] = Field(default_factory=list)
