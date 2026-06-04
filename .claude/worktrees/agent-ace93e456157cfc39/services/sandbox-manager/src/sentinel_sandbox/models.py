"""
Pydantic models for the Sentinel Sandbox Manager.

ValidationRequest  — comes from Convex (finding details + target)
ValidationResult   — sent back to Convex (outcome + PoC + evidence)
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class SandboxMode(str, Enum):
    HTTP_PROBE = "http_probe"  # Fire real HTTP requests at target_url
    DRY_RUN = "dry_run"        # Build PoC only — no live requests


class ExploitOutcome(str, Enum):
    EXPLOITED = "exploited"               # Confirmed exploitation
    LIKELY_EXPLOITABLE = "likely_exploitable"  # Strong signals, not definitive
    NOT_EXPLOITABLE = "not_exploitable"   # Tested, no evidence of exploitability
    ERROR = "error"                       # Sandbox error (unreachable, timeout, etc.)


class ExploitCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_BYPASS = "auth_bypass"
    SSRF = "ssrf"
    KNOWN_CVE = "known_cve"
    DEPENDENCY_EXPLOIT = "dependency_exploit"
    GENERIC_PROBE = "generic_probe"
    LLM_INJECTION = "llm_injection"  # Prompt injection / jailbreak against AI endpoints


# ── HTTP primitives ───────────────────────────────────────────────────────────

class HttpAttemptRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    timeout_seconds: float = 10.0


class HttpAttemptResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body_snippet: str  # First 2000 chars — never store full response
    elapsed_ms: float


class ExploitAttempt(BaseModel):
    """One attempt = one payload + the HTTP round-trip result."""
    payload_label: str          # Human-readable name, e.g. "sqli_union_1col"
    category: ExploitCategory
    request: HttpAttemptRequest
    response: Optional[HttpAttemptResponse] = None
    # Strings we look for in the response to declare success
    success_indicators: list[str] = Field(default_factory=list)
    matched_indicators: list[str] = Field(default_factory=list)
    success: bool = False
    skip_reason: Optional[str] = None  # Set when attempt is skipped (dry_run, etc.)


# ── Validation request / result ───────────────────────────────────────────────

class ValidationRequest(BaseModel):
    """Sent by Convex when a finding needs real sandbox validation."""
    finding_id: str
    repository_full_name: str
    vuln_class: str            # e.g. "sql_injection", "path_traversal"
    severity: str              # critical | high | medium | low
    affected_packages: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)

    # Where to probe. If absent → dry_run automatically.
    target_base_url: Optional[str] = None

    # Optional CVE ID for known-pattern matching
    cve_id: Optional[str] = None

    # Explicit mode override — default derives from target_base_url presence
    sandbox_mode: Optional[SandboxMode] = None

    max_attempts: int = Field(default=20, le=50)
    timeout_seconds: int = Field(default=30, le=120)

    @property
    def effective_mode(self) -> SandboxMode:
        if self.sandbox_mode is not None:
            return self.sandbox_mode
        return SandboxMode.HTTP_PROBE if self.target_base_url else SandboxMode.DRY_RUN


class ValidationResult(BaseModel):
    """Returned to Convex after validation completes."""
    finding_id: str
    outcome: ExploitOutcome
    confidence: float = Field(ge=0.0, le=1.0)

    # Bounded list — at most max_attempts items
    attempts: list[ExploitAttempt] = Field(default_factory=list)

    # Proof-of-concept artifacts (only populated when outcome != NOT_EXPLOITABLE)
    poc_curl: Optional[str] = None
    poc_python: Optional[str] = None

    evidence_summary: str
    sandbox_mode: SandboxMode
    elapsed_ms: float

    # Convenience: how many attempts succeeded
    @property
    def successful_attempt_count(self) -> int:
        return sum(1 for a in self.attempts if a.success)
