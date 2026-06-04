"""API endpoint tests using FastAPI's TestClient."""

from __future__ import annotations

from fastapi.testclient import TestClient

from src.http_server import build_app


def _client() -> TestClient:
    return TestClient(build_app())


def test_health_returns_ok() -> None:
    response = _client().get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_ingest_unknown_source_returns_404() -> None:
    response = _client().post("/ingest/not-a-real-source", json={})
    assert response.status_code == 404
    assert response.json()["error"].startswith("Unknown source")


def test_ingest_telegram_stub_returns_zero_events() -> None:
    response = _client().post("/ingest/telegram", json={"limit": 5})
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "telegram"
    assert body["fetched"] == 0
    assert body["events"] == []


def test_ingest_darkweb_stub_returns_zero_events() -> None:
    response = _client().post("/ingest/darkweb", json={})
    assert response.status_code == 200
    assert response.json()["fetched"] == 0


def test_correlate_endpoint_returns_matches() -> None:
    body = {
        "events": [
            {
                "source": "osv",
                "source_id": "GHSA-1",
                "title": "Example",
                "description": "",
                "severity": "high",
                "affected_packages": [
                    {
                        "ecosystem": "npm",
                        "name": "left-pad",
                        "version_range": "",
                        "fixed_version": "",
                    }
                ],
                "references": [],
                "tags": [],
            }
        ],
        "candidates": [
            {
                "tenant_id": "t1",
                "repo_url": "https://github.com/acme/app",
                "ecosystem": "npm",
                "name": "left-pad",
                "version": "1.0.0",
            }
        ],
    }
    response = _client().post("/correlate", json=body)
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["confidence"] == 1.0
    assert results[0]["source_event_id"] == "GHSA-1"


def test_correlate_endpoint_returns_empty_when_no_match() -> None:
    body = {
        "events": [
            {
                "source": "osv",
                "source_id": "GHSA-2",
                "title": "Example",
                "description": "",
                "severity": "medium",
                "affected_packages": [
                    {
                        "ecosystem": "npm",
                        "name": "some-other-pkg",
                        "version_range": "",
                        "fixed_version": "",
                    }
                ],
                "references": [],
                "tags": [],
            }
        ],
        "candidates": [
            {
                "tenant_id": "t1",
                "repo_url": "r",
                "ecosystem": "npm",
                "name": "left-pad",
                "version": "1.0.0",
            }
        ],
    }
    response = _client().post("/correlate", json=body)
    assert response.status_code == 200
    assert response.json()["results"] == []
