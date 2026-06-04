"""Match ingested breach events against tenant SBOM state.

Inputs are intentionally narrow: a list of BreachEvents and a list of
CorrelationCandidates (one per (tenant, repo, package) tuple from the
caller's SBOM store). The correlator is pure — it performs no network IO —
so callers are responsible for sourcing both sides.
"""

from __future__ import annotations

from .models import (
    BreachEvent,
    CorrelationCandidate,
    CorrelationResult,
)


def correlate(
    events: list[BreachEvent],
    candidates: list[CorrelationCandidate],
) -> list[CorrelationResult]:
    """Return a CorrelationResult per (event, candidate) match.

    Match rules:
      * Same ecosystem (case-insensitive) AND same package name
        (case-insensitive, exact). Confidence 1.0.
      * KEV entries (ecosystem="kev") use synthetic vendor/product names.
        We fall back to a substring match against the candidate package
        name. Confidence 0.6 to flag the weaker signal.
    """
    results: list[CorrelationResult] = []

    for candidate in candidates:
        cand_eco = candidate.ecosystem.lower()
        cand_name = candidate.name.lower()

        for event in events:
            for affected in event.affected_packages:
                aff_eco = affected.ecosystem.lower()
                aff_name = affected.name.lower()

                if aff_eco == "kev":
                    if cand_name and cand_name in aff_name:
                        results.append(
                            CorrelationResult(
                                tenant_id=candidate.tenant_id,
                                repo_url=candidate.repo_url,
                                matched_package=affected,
                                source_event_id=event.source_id,
                                confidence=0.6,
                                rationale=(
                                    f"KEV vendor/product substring match for "
                                    f"{candidate.name}"
                                ),
                            )
                        )
                    continue

                if aff_eco == cand_eco and aff_name == cand_name:
                    results.append(
                        CorrelationResult(
                            tenant_id=candidate.tenant_id,
                            repo_url=candidate.repo_url,
                            matched_package=affected,
                            source_event_id=event.source_id,
                            confidence=1.0,
                            rationale=(
                                f"Exact ecosystem+name match against "
                                f"{event.source.value}:{event.source_id}"
                            ),
                        )
                    )

    return results
