"""
Tests for classify_outcome() — the core exploit-evidence decision function.
"""

import pytest

from sentinel_sandbox.executor import classify_outcome
from sentinel_sandbox.models import (
    ExploitAttempt,
    ExploitCategory,
    ExploitOutcome,
    HttpAttemptRequest,
    HttpAttemptResponse,
    SandboxMode,
    ValidationRequest,
)


def _req(severity: str = "high", mode: SandboxMode = SandboxMode.HTTP_PROBE) -> ValidationRequest:
    return ValidationRequest(
        finding_id="f1",
        repository_full_name="acme/api",
        vuln_class="sql_injection",
        severity=severity,
        sandbox_mode=mode,
    )


def _attempt(
    success: bool = False,
    matched: list[str] | None = None,
    status: int = 200,
    body: str = "ok",
    response: bool = True,
) -> ExploitAttempt:
    return ExploitAttempt(
        payload_label="test",
        category=ExploitCategory.SQL_INJECTION,
        request=HttpAttemptRequest(method="GET", url="http://t/"),
        response=HttpAttemptResponse(
            status_code=status,
            headers={},
            body_snippet=body,
            elapsed_ms=10.0,
        ) if response else None,
        matched_indicators=matched or [],
        success=success,
    )


class TestDryRun:
    def test_dry_run_always_not_exploitable(self):
        req = _req(mode=SandboxMode.DRY_RUN)
        outcome, conf = classify_outcome([], req)
        assert outcome == ExploitOutcome.NOT_EXPLOITABLE
        assert conf == 0.0

    def test_dry_run_ignores_success_flags(self):
        req = _req(mode=SandboxMode.DRY_RUN)
        attempts = [_attempt(success=True, matched=["root:x:0:0"], response=False)]
        outcome, _ = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.NOT_EXPLOITABLE


class TestNoExecutedAttempts:
    def test_no_responses_returns_error(self):
        req = _req()
        attempts = [_attempt(response=False), _attempt(response=False)]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.ERROR
        assert conf == 0.0


class TestDefinitiveIndicators:
    def test_root_passwd_is_definitive(self):
        req = _req(severity="critical")
        attempts = [_attempt(success=True, matched=["root:x:0:0"], body="root:x:0:0:root:/root:/bin/bash")]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.EXPLOITED
        assert conf >= 0.85

    def test_uid_output_is_definitive(self):
        req = _req(severity="high")
        attempts = [_attempt(success=True, matched=["uid=0("], body="uid=0(root)")]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.EXPLOITED

    def test_gid_output_is_definitive(self):
        req = _req()
        attempts = [_attempt(success=True, matched=["gid="], body="uid=1000 gid=1000")]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.EXPLOITED

    def test_jndi_reflection_is_definitive(self):
        req = _req(severity="critical")
        attempts = [_attempt(success=True, matched=["jndi:ldap"], body="jndi:ldap error")]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.EXPLOITED

    def test_critical_severity_boosts_confidence(self):
        req_critical = _req(severity="critical")
        req_low = _req(severity="low")
        a = _attempt(success=True, matched=["uid=0("])
        _, conf_critical = classify_outcome([a], req_critical)
        a2 = _attempt(success=True, matched=["uid=0("])
        _, conf_low = classify_outcome([a2], req_low)
        assert conf_critical > conf_low


class TestCorroborationRule:
    def test_two_weak_successes_become_exploited(self):
        req = _req()
        attempts = [
            _attempt(success=True, matched=["SQL syntax"]),
            _attempt(success=True, matched=["error"]),
        ]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.EXPLOITED
        assert conf >= 0.65

    def test_three_weak_successes_high_confidence(self):
        req = _req(severity="critical")
        attempts = [
            _attempt(success=True, matched=["SQL"]),
            _attempt(success=True, matched=["syntax"]),
            _attempt(success=True, matched=["error"]),
        ]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.EXPLOITED
        assert conf >= 0.75

    def test_confidence_capped_at_1_0(self):
        req = _req(severity="critical")
        attempts = [_attempt(success=True, matched=["uid=0("]) for _ in range(10)]
        _, conf = classify_outcome(attempts, req)
        assert conf <= 1.0


class TestLikelyExploitable:
    def test_single_weak_success_is_likely(self):
        req = _req()
        attempts = [_attempt(success=True, matched=["SQL syntax"])]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.LIKELY_EXPLOITABLE
        assert 0.3 <= conf <= 0.8

    def test_error_response_with_sql_keyword_is_likely(self):
        req = _req()
        attempts = [_attempt(success=False, status=500, body="You have an error in your SQL syntax")]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.LIKELY_EXPLOITABLE

    def test_error_response_with_traceback_is_likely(self):
        req = _req()
        attempts = [_attempt(success=False, status=500, body="Traceback (most recent call last)")]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.LIKELY_EXPLOITABLE


class TestNotExploitable:
    def test_all_200s_no_indicators_is_safe(self):
        req = _req()
        attempts = [_attempt(success=False, status=200, body="ok") for _ in range(5)]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.NOT_EXPLOITABLE
        assert conf < 0.2

    def test_404s_no_indicators_is_safe(self):
        req = _req()
        attempts = [_attempt(success=False, status=404, body="not found") for _ in range(5)]
        outcome, conf = classify_outcome(attempts, req)
        assert outcome == ExploitOutcome.NOT_EXPLOITABLE
