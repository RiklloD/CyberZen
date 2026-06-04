"""Correlation logic tests."""

from __future__ import annotations

from src.correlator import correlate
from src.models import (
    AffectedPackage,
    BreachEvent,
    BreachSource,
    CorrelationCandidate,
    Severity,
)


def _event(
    source: BreachSource,
    source_id: str,
    packages: list[AffectedPackage],
) -> BreachEvent:
    return BreachEvent(
        source=source,
        source_id=source_id,
        title=source_id,
        severity=Severity.HIGH,
        affected_packages=packages,
    )


def test_exact_match_emits_full_confidence() -> None:
    events = [
        _event(
            BreachSource.OSV,
            "GHSA-1",
            [AffectedPackage(ecosystem="npm", name="left-pad")],
        )
    ]
    candidates = [
        CorrelationCandidate(
            tenant_id="t1",
            repo_url="https://github.com/acme/app",
            ecosystem="npm",
            name="left-pad",
            version="1.0.0",
        )
    ]

    results = correlate(events, candidates)
    assert len(results) == 1
    assert results[0].confidence == 1.0
    assert results[0].source_event_id == "GHSA-1"
    assert results[0].tenant_id == "t1"


def test_case_insensitive_ecosystem_and_name() -> None:
    events = [
        _event(
            BreachSource.OSV,
            "GHSA-2",
            [AffectedPackage(ecosystem="NPM", name="Left-Pad")],
        )
    ]
    candidates = [
        CorrelationCandidate(
            tenant_id="t1",
            repo_url="r",
            ecosystem="npm",
            name="left-pad",
            version="1.0.0",
        )
    ]
    assert len(correlate(events, candidates)) == 1


def test_kev_substring_match_is_lower_confidence() -> None:
    events = [
        _event(
            BreachSource.CISA_KEV,
            "CVE-2025-1",
            [AffectedPackage(ecosystem="kev", name="Acme/Widget")],
        )
    ]
    candidates = [
        CorrelationCandidate(
            tenant_id="t1",
            repo_url="r",
            ecosystem="npm",
            name="widget",
            version="1.0.0",
        )
    ]
    results = correlate(events, candidates)
    assert len(results) == 1
    assert results[0].confidence == 0.6
    assert "KEV" in results[0].rationale


def test_no_match_returns_empty() -> None:
    events = [
        _event(
            BreachSource.OSV,
            "GHSA-3",
            [AffectedPackage(ecosystem="npm", name="something-else")],
        )
    ]
    candidates = [
        CorrelationCandidate(
            tenant_id="t1",
            repo_url="r",
            ecosystem="npm",
            name="left-pad",
            version="1.0.0",
        )
    ]
    assert correlate(events, candidates) == []


def test_ecosystem_mismatch_blocks_match() -> None:
    events = [
        _event(
            BreachSource.OSV,
            "GHSA-4",
            [AffectedPackage(ecosystem="npm", name="left-pad")],
        )
    ]
    candidates = [
        CorrelationCandidate(
            tenant_id="t1",
            repo_url="r",
            ecosystem="PyPI",
            name="left-pad",
            version="1.0.0",
        )
    ]
    assert correlate(events, candidates) == []
