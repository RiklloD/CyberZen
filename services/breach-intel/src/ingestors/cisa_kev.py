"""CISA Known Exploited Vulnerabilities ingestor.

Pulls the public KEV catalog (JSON) and maps each entry into a BreachEvent.
KEV does not include affected package metadata at the ecosystem level, so
matches are done by CVE and product/vendor strings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ..models import (
    AffectedPackage,
    BreachEvent,
    BreachSource,
    IngestRequest,
    Severity,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevIngestor:
    source_name = "cisa_kev"

    def __init__(self, client: httpx.AsyncClient | None = None, url: str = KEV_URL) -> None:
        self._client = client
        self._owns_client = client is None
        self.url = url

    async def fetch(self, request: IngestRequest) -> list[BreachEvent]:
        client = self._client or httpx.AsyncClient(timeout=30.0)
        try:
            response = await client.get(self.url)
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        finally:
            if self._owns_client:
                await client.aclose()

        events: list[BreachEvent] = []
        vulnerabilities: list[dict[str, Any]] = payload.get("vulnerabilities", [])
        for entry in vulnerabilities[: request.limit]:
            events.append(self._map_entry(entry))
        return events

    @staticmethod
    def _map_entry(entry: dict[str, Any]) -> BreachEvent:
        cve_id: str = entry.get("cveID", "")
        product: str = entry.get("product", "")
        vendor: str = entry.get("vendorProject", "")
        date_added_raw: str = entry.get("dateAdded", "")
        published_at: datetime | None = None
        if date_added_raw:
            try:
                published_at = datetime.fromisoformat(date_added_raw).replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                published_at = None

        affected = AffectedPackage(
            ecosystem="kev",
            name=f"{vendor}/{product}".strip("/"),
            version_range="",
            fixed_version="",
        )

        return BreachEvent(
            source=BreachSource.CISA_KEV,
            source_id=cve_id or entry.get("vulnerabilityName", ""),
            title=entry.get("vulnerabilityName", cve_id),
            description=entry.get("shortDescription", ""),
            severity=Severity.HIGH,
            affected_packages=[affected],
            published_at=published_at,
            references=[],
            tags=["actively-exploited", "kev"],
        )
