"""
Exploit Executor — the core of the Sandbox Manager.

Flow:
  1. Select exploit modules for the finding's vuln_class
  2. Generate ExploitAttempt specs from each module
  3. Execute attempts via httpx (skip in dry_run mode)
  4. classify_outcome() — *** SEE USER CONTRIBUTION BELOW ***
  5. Generate PoC for the winning attempt
  6. Return ValidationResult
"""

from __future__ import annotations

import time
from typing import Sequence

import httpx

from .exploits import AuthBypassModule, HttpProbeModule, InjectionModule, LlmInjectionModule
from .exploits.base import ExploitModule
from .exploits.cve_patterns import patterns_for_cve, patterns_for_package, patterns_for_vuln_class
from .models import (
    ExploitAttempt,
    ExploitCategory,
    ExploitOutcome,
    HttpAttemptRequest,
    HttpAttemptResponse,
    SandboxMode,
    ValidationRequest,
    ValidationResult,
)
from .poc import build_curl_poc, build_python_poc

# ── Module registry ───────────────────────────────────────────────────────────

_MODULES: list[ExploitModule] = [
    HttpProbeModule(),
    InjectionModule(),
    AuthBypassModule(),
    LlmInjectionModule(),
]


# ── Public entry point ────────────────────────────────────────────────────────

async def run_validation(req: ValidationRequest) -> ValidationResult:
    """
    Orchestrate a full validation run for a single finding.
    Returns a ValidationResult regardless of outcome or error.
    """
    start = time.monotonic()

    try:
        result = await _execute(req)
    except Exception as exc:  # noqa: BLE001
        elapsed = (time.monotonic() - start) * 1000
        return ValidationResult(
            finding_id=req.finding_id,
            outcome=ExploitOutcome.ERROR,
            confidence=0.0,
            attempts=[],
            evidence_summary=f"Executor error: {exc}",
            sandbox_mode=req.effective_mode,
            elapsed_ms=elapsed,
        )

    result.elapsed_ms = (time.monotonic() - start) * 1000
    return result


# ── Internal orchestration ────────────────────────────────────────────────────

async def _execute(req: ValidationRequest) -> ValidationResult:
    mode = req.effective_mode
    base_url = (req.target_base_url or "http://localhost:8080").rstrip("/")

    # 1 — Collect attempts from all applicable modules
    all_attempts: list[ExploitAttempt] = []

    for module in _MODULES:
        if module.can_handle(req.vuln_class):
            all_attempts.extend(module.generate_attempts(req, base_url))

    # 2 — Add CVE-specific patterns (cve_id or package match)
    all_attempts.extend(_cve_attempts(req, base_url))

    # 3 — Cap total attempts
    all_attempts = all_attempts[: req.max_attempts]

    # 4 — Execute (or mark skipped in dry_run)
    executed = await _run_attempts(all_attempts, mode, req.timeout_seconds)

    # 5 — Classify
    outcome, confidence = classify_outcome(executed, req)

    # 6 — PoC from first successful attempt
    poc_curl: str | None = None
    poc_python: str | None = None
    winning = next((a for a in executed if a.success), None)
    if winning and outcome in (ExploitOutcome.EXPLOITED, ExploitOutcome.LIKELY_EXPLOITABLE):
        poc_curl = build_curl_poc(winning)
        poc_python = build_python_poc(winning)

    return ValidationResult(
        finding_id=req.finding_id,
        outcome=outcome,
        confidence=confidence,
        attempts=executed,
        poc_curl=poc_curl,
        poc_python=poc_python,
        evidence_summary=_summarise(executed, outcome, mode),
        sandbox_mode=mode,
        elapsed_ms=0.0,  # filled by run_validation
    )


# ── ★ USER CONTRIBUTION ───────────────────────────────────────────────────────

def classify_outcome(
    attempts: list[ExploitAttempt],
    req: ValidationRequest,
) -> tuple[ExploitOutcome, float]:
    """
    Given the executed attempts, decide the exploit outcome and confidence.

    Parameters
    ----------
    attempts : list[ExploitAttempt]
        Fully executed attempts — each has .success, .matched_indicators,
        .response (status_code, body_snippet, elapsed_ms), and .category.

    req : ValidationRequest
        Original request — use req.severity, req.vuln_class, req.effective_mode
        for context-sensitive decisions.

    Returns
    -------
    (ExploitOutcome, confidence: float 0.0–1.0)

    Outcome options
    ---------------
    ExploitOutcome.EXPLOITED           — definitive evidence of exploitation
    ExploitOutcome.LIKELY_EXPLOITABLE  — strong signals, not definitive
    ExploitOutcome.NOT_EXPLOITABLE     — tested, no evidence found
    ExploitOutcome.ERROR               — sandbox couldn't run (use sparingly)

    Design considerations
    ----------------------
    This function shapes Sentinel's false-positive rate — the spec's core
    promise is "silence is safe". Two failure modes:

      • Too strict  → real exploits missed, developers get a false sense of safety
      • Too lenient → fake alerts, developers stop trusting Sentinel

    Things to consider:
    - How many attempts need to succeed before you're confident?
    - Does a 500 error + SQL keyword in the response count as "exploited"?
    - Should timing-based payloads (SLEEP) get a lower confidence than direct evidence?
    - Does severity of the finding affect how aggressively you classify?
    - Should dry_run mode (no live requests) return NOT_EXPLOITABLE or a special value?

    Design rationale
    ----------------
    We use a confidence-tiered model that requires *increasing* evidence
    strength to reach EXPLOITED.  A single weak indicator match is never
    enough — it must either be corroborated by a second independent attempt
    OR the matched indicator must be unambiguously data-exfiltration evidence
    (e.g. "root:x:0:0" from /etc/passwd, "uid=0" from command injection).

    Dry-run produces no live evidence, so it returns NOT_EXPLOITABLE at 0.0
    rather than ERROR — the finding still exists; it just hasn't been probed.
    """
    # ── Dry-run: no live requests were fired ──────────────────────────────
    if req.effective_mode == SandboxMode.DRY_RUN:
        return ExploitOutcome.NOT_EXPLOITABLE, 0.0

    # ── Categorise attempts ───────────────────────────────────────────────
    executed = [a for a in attempts if a.response is not None]
    successes = [a for a in executed if a.success]

    if not executed:
        # Nothing reached the target at all
        return ExploitOutcome.ERROR, 0.0

    # ── Strong unambiguous indicators ────────────────────────────────────
    # HTTP exploit indicators: OS/server disclosure strings that cannot appear
    # in a legitimate response.
    # LLM canary indicators: unique phrases the model would only echo if hijacked —
    # a compliant AI would never produce these without explicit injection.
    DEFINITIVE = {
        # HTTP / OS
        "root:x:0:0", "root:", "uid=0(", "uid=", "gid=", "/bin/bash",
        "document_root", "jndi:ldap", "Exception in thread",
        # LLM injection canaries
        "sentinel_canary_4829", "sentinel_canary_7163",
        "sentinel_rag_pwned", "tool_injected_8521",
        "override_active", "i am dan",
    }

    def _is_definitive(attempt: ExploitAttempt) -> bool:
        return any(ind in DEFINITIVE for ind in attempt.matched_indicators)

    definitive_hits = [a for a in successes if _is_definitive(a)]

    # ── Classification ────────────────────────────────────────────────────
    severity_weight = {"critical": 1.2, "high": 1.1, "medium": 1.0, "low": 0.85}.get(
        req.severity, 1.0
    )

    if definitive_hits:
        # Any definitive indicator = confirmed exploitation
        raw_confidence = 0.85 + (0.05 * min(len(definitive_hits), 3))
        return ExploitOutcome.EXPLOITED, min(1.0, round(raw_confidence * severity_weight, 2))

    if len(successes) >= 2:
        # Two independent payloads both matched → strong corroboration
        raw_confidence = 0.70 + (0.03 * min(len(successes), 5))
        return ExploitOutcome.EXPLOITED, min(1.0, round(raw_confidence * severity_weight, 2))

    if len(successes) == 1:
        # Single non-definitive match → likely but not confirmed
        return ExploitOutcome.LIKELY_EXPLOITABLE, round(0.50 * severity_weight, 2)

    # ── Weak signal: 4xx/5xx on injection endpoints suggests error-leakage
    error_responses = [
        a for a in executed
        if a.response and a.response.status_code >= 400
        and any(kw in a.response.body_snippet.lower()
                for kw in ("sql", "syntax", "error", "exception", "traceback"))
    ]
    if error_responses:
        return ExploitOutcome.LIKELY_EXPLOITABLE, round(0.30 * severity_weight, 2)

    return ExploitOutcome.NOT_EXPLOITABLE, 0.05


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cve_attempts(req: ValidationRequest, base_url: str) -> list[ExploitAttempt]:
    """Build ExploitAttempts from CVE pattern registry."""
    patterns = []
    if req.cve_id:
        patterns = patterns_for_cve(req.cve_id)
    if not patterns:
        patterns = patterns_for_vuln_class(req.vuln_class)
    if not patterns:
        for pkg in req.affected_packages:
            patterns.extend(patterns_for_package(pkg))

    attempts = []
    for p in patterns:
        url = base_url.rstrip("/") + p.path
        if p.query_params:
            qs = "&".join(f"{k}={v}" for k, v in p.query_params.items())
            url = f"{url}?{qs}"
        attempts.append(
            ExploitAttempt(
                payload_label=p.label,
                category=ExploitCategory.KNOWN_CVE,
                request=HttpAttemptRequest(
                    method=p.method,
                    url=url,
                    headers={"User-Agent": "Sentinel-Security-Agent/1.0", **p.headers},
                    body=p.body,
                ),
                success_indicators=list(p.success_indicators),
            )
        )
    return attempts


async def _run_attempts(
    attempts: list[ExploitAttempt],
    mode: SandboxMode,
    timeout: int,
) -> list[ExploitAttempt]:
    """Execute each attempt; mark success based on indicator matching."""
    if mode == SandboxMode.DRY_RUN:
        for a in attempts:
            a.skip_reason = "dry_run"
        return attempts

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,  # sandbox environments use self-signed certs
    ) as client:
        for attempt in attempts:
            attempt = await _fire(client, attempt)

    return attempts


async def _fire(client: httpx.AsyncClient, attempt: ExploitAttempt) -> ExploitAttempt:
    """Fire a single HTTP attempt and populate .response + .success."""
    req = attempt.request
    try:
        t0 = time.monotonic()
        resp = await client.request(
            method=req.method,
            url=req.url,
            headers=req.headers,
            content=req.body.encode() if req.body else None,
            timeout=req.timeout_seconds,
        )
        elapsed = (time.monotonic() - t0) * 1000
        body_snippet = resp.text[:2000]

        attempt.response = HttpAttemptResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body_snippet=body_snippet,
            elapsed_ms=elapsed,
        )

        # Match success indicators against response body + status
        check_text = f"{resp.status_code} {body_snippet}".lower()
        matched = [ind for ind in attempt.success_indicators if ind.lower() in check_text]
        attempt.matched_indicators = matched
        attempt.success = len(matched) > 0

    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        attempt.skip_reason = str(exc)

    return attempt


def _summarise(
    attempts: list[ExploitAttempt], outcome: ExploitOutcome, mode: SandboxMode
) -> str:
    total = len(attempts)
    executed = sum(1 for a in attempts if a.response is not None)
    succeeded = sum(1 for a in attempts if a.success)

    if mode == SandboxMode.DRY_RUN:
        return f"Dry-run mode: {total} exploit patterns generated, not executed."

    if outcome == ExploitOutcome.EXPLOITED:
        winning = next(a for a in attempts if a.success)
        return (
            f"Exploitation confirmed — {winning.payload_label} succeeded "
            f"({len(winning.matched_indicators)} indicator(s) matched). "
            f"{executed}/{total} attempts executed."
        )
    if outcome == ExploitOutcome.LIKELY_EXPLOITABLE:
        return (
            f"Likely exploitable — {succeeded}/{executed} attempts matched indicators. "
            "Definitive confirmation requires manual verification."
        )
    if outcome == ExploitOutcome.NOT_EXPLOITABLE:
        return (
            f"No exploitation evidence found across {executed} attempts. "
            "Component may be unexploitable in this configuration."
        )
    return f"Validation error after {executed} attempts."
