"""Unit tests for each ingestor.

External HTTP calls are stubbed via httpx.MockTransport so the suite runs
fully offline.
"""

from __future__ import annotations

import json

import httpx
import pytest

from src.ingestors import (
    CisaKevIngestor,
    DarkwebIngestor,
    OsvIngestor,
    TelegramIngestor,
)
from src.models import BreachSource, IngestRequest


@pytest.mark.asyncio
async def test_telegram_stub_returns_empty_list() -> None:
    ingestor = TelegramIngestor(channels=["@some_channel"])
    events = await ingestor.fetch(IngestRequest())
    assert events == []


@pytest.mark.asyncio
async def test_darkweb_stub_returns_empty_list() -> None:
    ingestor = DarkwebIngestor()
    events = await ingestor.fetch(IngestRequest())
    assert events == []


@pytest.mark.asyncio
async def test_cisa_kev_maps_entries() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2025-12345",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "dateAdded": "2025-03-01",
                "shortDescription": "Remote code execution in Acme Widget.",
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(payload))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ingestor = CisaKevIngestor(client=client)
        events = await ingestor.fetch(IngestRequest(limit=10))

    assert len(events) == 1
    event = events[0]
    assert event.source is BreachSource.CISA_KEV
    assert event.source_id == "CVE-2025-12345"
    assert event.affected_packages[0].name == "Acme/Widget"
    assert "actively-exploited" in event.tags


@pytest.mark.asyncio
async def test_cisa_kev_respects_limit() -> None:
    payload = {
        "vulnerabilities": [
            {"cveID": f"CVE-2025-{i:05d}", "vendorProject": "v", "product": "p"}
            for i in range(5)
        ]
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(payload))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ingestor = CisaKevIngestor(client=client)
        events = await ingestor.fetch(IngestRequest(limit=2))
    assert len(events) == 2


@pytest.mark.asyncio
async def test_osv_skips_when_no_packages_specified() -> None:
    ingestor = OsvIngestor()
    assert await ingestor.fetch(IngestRequest()) == []


@pytest.mark.asyncio
async def test_osv_queries_each_package() -> None:
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Example advisory",
                            "details": "Detailed description.",
                            "references": [{"url": "https://example.com/adv"}],
                            "published": "2025-04-01T00:00:00Z",
                        }
                    ]
                }
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ingestor = OsvIngestor(client=client)
        request = IngestRequest(
            extra={
                "packages": [
                    {"ecosystem": "npm", "name": "left-pad", "version": "1.0.0"},
                    {"ecosystem": "PyPI", "name": "requests"},
                ]
            }
        )
        events = await ingestor.fetch(request)

    assert len(calls) == 2
    assert calls[0]["package"]["name"] == "left-pad"
    assert len(events) == 2
    assert events[0].source is BreachSource.OSV
    assert events[0].source_id == "GHSA-xxxx-yyyy-zzzz"
