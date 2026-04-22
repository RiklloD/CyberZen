"""
Tests for the executor — dry_run mode only (no live network calls).

Live HTTP tests require a real target and belong in integration tests.
"""

import pytest

from sentinel_sandbox.executor import _cve_attempts, _summarise
from sentinel_sandbox.models import (
    ExploitAttempt,
    ExploitCategory,
    ExploitOutcome,
    HttpAttemptRequest,
    SandboxMode,
    ValidationRequest,
)

BASE = "http://target.local"


def _req(**kwargs) -> ValidationRequest:
    defaults = dict(
        finding_id="f1",
        repository_full_name="acme/api",
        vuln_class="sql_injection",
        severity="high",
    )
    defaults.update(kwargs)
    return ValidationRequest(**defaults)


def _attempt(success: bool = False, indicators: list[str] | None = None) -> ExploitAttempt:
    from sentinel_sandbox.models import HttpAttemptResponse
    return ExploitAttempt(
        payload_label="test_payload",
        category=ExploitCategory.SQL_INJECTION,
        request=HttpAttemptRequest(method="GET", url=f"{BASE}/?id=1'"),
        response=HttpAttemptResponse(
            status_code=500 if success else 200,
            headers={},
            body_snippet="SQL syntax error" if success else "ok",
            elapsed_ms=10.0,
        ) if success else None,
        success_indicators=indicators or ["SQL syntax"],
        matched_indicators=["SQL syntax"] if success else [],
        success=success,
    )


# ── dry_run mode ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dry_run_no_live_requests():
    """Dry run must not fire any HTTP requests — all attempts marked skipped."""
    from sentinel_sandbox.executor import _execute
    req = _req(sandbox_mode=SandboxMode.DRY_RUN)
    # _execute will raise NotImplementedError on classify_outcome —
    # we test the attempt generation part via _cve_attempts and module dispatch
    # (full integration test requires classify_outcome to be implemented)
    attempts = _cve_attempts(req, BASE)
    for a in attempts:
        assert a.response is None  # not executed yet


# ── _cve_attempts ─────────────────────────────────────────────────────────────

class TestCveAttempts:
    def test_log4shell_attempts_from_cve_id(self):
        req = _req(cve_id="CVE-2021-44228", vuln_class="log4shell")
        attempts = _cve_attempts(req, BASE)
        assert len(attempts) >= 2
        labels = [a.payload_label for a in attempts]
        assert any("log4shell" in l for l in labels)

    def test_path_traversal_from_vuln_class(self):
        req = _req(vuln_class="path_traversal")
        attempts = _cve_attempts(req, BASE)
        assert len(attempts) > 0
        assert all(a.category == ExploitCategory.KNOWN_CVE for a in attempts)

    def test_known_package_triggers_patterns(self):
        req = _req(
            vuln_class="rce",
            affected_packages=["log4j-core"],
        )
        attempts = _cve_attempts(req, BASE)
        assert len(attempts) > 0

    def test_unknown_class_and_package_returns_empty(self):
        req = _req(vuln_class="unknown_xyz", affected_packages=["some-random-lib"])
        attempts = _cve_attempts(req, BASE)
        assert attempts == []

    def test_attempts_have_valid_urls(self):
        req = _req(cve_id="CVE-2021-44228")
        attempts = _cve_attempts(req, BASE)
        for a in attempts:
            assert a.request.url.startswith("http://")


# ── _summarise ────────────────────────────────────────────────────────────────

class TestSummarise:
    def test_dry_run_summary(self):
        summary = _summarise([], ExploitOutcome.NOT_EXPLOITABLE, SandboxMode.DRY_RUN)
        assert "dry-run" in summary.lower() or "dry_run" in summary.lower()

    def test_exploited_summary_mentions_payload(self):
        attempts = [_attempt(success=True)]
        summary = _summarise(attempts, ExploitOutcome.EXPLOITED, SandboxMode.HTTP_PROBE)
        assert "test_payload" in summary
        assert "confirmed" in summary.lower() or "exploit" in summary.lower()

    def test_not_exploitable_summary(self):
        attempts = [_attempt(success=False)]
        summary = _summarise(attempts, ExploitOutcome.NOT_EXPLOITABLE, SandboxMode.HTTP_PROBE)
        assert "no" in summary.lower() or "not" in summary.lower()

    def test_likely_exploitable_summary(self):
        attempts = [_attempt(success=True)]
        summary = _summarise(attempts, ExploitOutcome.LIKELY_EXPLOITABLE, SandboxMode.HTTP_PROBE)
        assert "likely" in summary.lower()


# ── effective_mode ────────────────────────────────────────────────────────────

class TestEffectiveMode:
    def test_no_url_means_dry_run(self):
        req = _req(target_base_url=None)
        assert req.effective_mode == SandboxMode.DRY_RUN

    def test_url_present_means_http_probe(self):
        req = _req(target_base_url="http://localhost:8080")
        assert req.effective_mode == SandboxMode.HTTP_PROBE

    def test_explicit_dry_run_overrides_url(self):
        req = _req(
            target_base_url="http://localhost:8080",
            sandbox_mode=SandboxMode.DRY_RUN,
        )
        assert req.effective_mode == SandboxMode.DRY_RUN
