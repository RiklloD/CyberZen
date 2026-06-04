"""OSV (osv.dev) API client.

The OSV API exposes per-package vulnerability lookups. This ingestor queries
the `/v1/query` endpoint by package and emits one BreachEvent per
vulnerability returned. Callers may pass an explicit package list via
`IngestRequest.extra["packages"]`; otherwise the call is a no-op so that
scheduling the endpoint cheaply does not incur API spend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from ..models import (
    AffectedPackage,
    BreachEvent,
    BreachSource,
    IngestRequest,
    Severity,
)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvIngestor:
    source_name = "osv"

    def __init__(self, client: httpx.AsyncClient | None = None, url: str = OSV_QUERY_URL) -> None:
        self._client = client
        self._owns_client = client is None
        self.url = url

    async def fetch(self, request: IngestRequest) -> list[BreachEvent]:
        packages: list[dict[str, str]] = list(request.extra.get("packages", []))  # type: ignore[arg-type]
        if not packages:
            return []

        client = self._client or httpx.AsyncClient(timeout=30.0)
        events: list[BreachEvent] = []
        try:
            for spec in packages[: request.limit]:
                body = {
                    "package": {
                        "name": spec["name"],
                        "ecosystem": spec["ecosystem"],
                    }
                }
                if "version" in spec:
                    body["version"] = spec["version"]
                response = await client.post(self.url, json=body)
                response.raise_for_status()
                payload: dict[str, Any] = response.json()
                for vuln in payload.get("vulns", []):
                    events.append(self._map_vuln(vuln, spec))
        finally:
            if self._owns_client:
                await client.aclose()
        return events

    @staticmethod
    def _map_vuln(vuln: dict[str, Any], spec: dict[str, str]) -> BreachEvent:
        published_raw: str = vuln.get("published", "")
        published_at: datetime | None = None
        if published_raw:
            try:
                published_at = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
            except ValueError:
                published_at = None

        severity = Severity.MEDIUM
        for sev in vuln.get("severity", []):
            label = (sev.get("type") or "").lower()
            if label == "cvss_v3":
                score = sev.get("score") or ""
                if "/AV" in score:
                    # CVSS vector string — rely on database_specific instead.
                    pass

        return BreachEvent(
            source=BreachSource.OSV,
            source_id=vuln.get("id", ""),
            title=vuln.get("summary", vuln.get("id", "OSV advisory")),
            description=vuln.get("details", ""),
            severity=severity,
            affected_packages=[
                AffectedPackage(
                    ecosystem=spec["ecosystem"],
                    name=spec["name"],
                    version_range="",
                    fixed_version="",
                )
            ],
            published_at=published_at,
            references=[ref["url"] for ref in vuln.get("references", []) if ref.get("url")],
            tags=["osv"],
        )
