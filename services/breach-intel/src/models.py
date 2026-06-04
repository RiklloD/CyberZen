"""Pydantic models exchanged over the breach-intel HTTP API.

These mirror the shared protobuf contracts in `services/shared/contracts`
but stay independently versioned so the service can ship before the
generated bindings are wired in.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BreachSource(str, Enum):
    CISA_KEV = "cisa_kev"
    OSV = "osv"
    TELEGRAM = "telegram"
    DARKWEB = "darkweb"
    GHSA = "ghsa"
    NVD = "nvd"
    VENDOR = "vendor"


class AffectedPackage(BaseModel):
    ecosystem: str
    name: str
    version_range: str = Field(default="")
    fixed_version: str = Field(default="")


class BreachEvent(BaseModel):
    source: BreachSource
    source_id: str
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    published_at: datetime | None = None
    ingested_at: datetime | None = None
    references: list[HttpUrl] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class CorrelationCandidate(BaseModel):
    """A single SBOM entry to correlate against ingested breach events."""

    tenant_id: str
    repo_url: str
    ecosystem: str
    name: str
    version: str


class CorrelationResult(BaseModel):
    tenant_id: str
    repo_url: str
    matched_package: AffectedPackage
    source_event_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class IngestRequest(BaseModel):
    """Optional payload posted to /ingest/{source}. Empty body is allowed —
    sources that pull from external APIs use the source name in the path
    only and ignore the body."""

    cursor: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    extra: dict[str, Any] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    source: BreachSource
    fetched: int
    new_events: int
    cursor: str | None = None
    events: list[BreachEvent] = Field(default_factory=list)


class CorrelateRequest(BaseModel):
    events: list[BreachEvent]
    candidates: list[CorrelationCandidate]


class CorrelateResponse(BaseModel):
    results: list[CorrelationResult]


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
