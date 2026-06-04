"""HTTP routing for the breach-intel service.

The FastAPI app is assembled here so `main.py` stays focused on lifecycle
(uvicorn entrypoint, startup logging). Routers live on the module-level
APIRouter and are mounted by `build_app()`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .correlator import correlate
from .ingestors import (
    CisaKevIngestor,
    DarkwebIngestor,
    Ingestor,
    OsvIngestor,
    TelegramIngestor,
)
from .models import (
    BreachSource,
    CorrelateRequest,
    CorrelateResponse,
    HealthResponse,
    IngestRequest,
    IngestResponse,
)

log = logging.getLogger(__name__)

router = APIRouter()


def _registry() -> dict[BreachSource, Ingestor]:
    """Build a fresh registry per request so tests can swap implementations."""
    return {
        BreachSource.CISA_KEV: CisaKevIngestor(),
        BreachSource.OSV: OsvIngestor(),
        BreachSource.TELEGRAM: TelegramIngestor(),
        BreachSource.DARKWEB: DarkwebIngestor(),
    }


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@router.post("/ingest/{source}", response_model=IngestResponse)
async def ingest(source: str, request: IngestRequest | None = None) -> IngestResponse:
    try:
        breach_source = BreachSource(source)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown source: {source}") from exc

    registry = _registry()
    ingestor = registry.get(breach_source)
    if ingestor is None:
        raise HTTPException(status_code=501, detail=f"No ingestor wired for {source}")

    payload = request or IngestRequest()
    events = await ingestor.fetch(payload)
    now = datetime.now(tz=timezone.utc)
    for event in events:
        if event.ingested_at is None:
            event.ingested_at = now

    return IngestResponse(
        source=breach_source,
        fetched=len(events),
        new_events=len(events),
        cursor=payload.cursor,
        events=events,
    )


@router.post("/correlate", response_model=CorrelateResponse)
async def correlate_endpoint(request: CorrelateRequest) -> CorrelateResponse:
    results = correlate(request.events, request.candidates)
    return CorrelateResponse(results=results)


def build_app() -> FastAPI:
    app = FastAPI(
        title="CyberZen Breach Intel",
        version=__version__,
        description="Breach intelligence ingest + SBOM correlation service.",
    )

    app.add_middleware(
        CORSMiddleware,
        # The service is intended to be called server-to-server from Convex
        # actions. CORS is permissive on the assumption network-level ACLs
        # restrict reachability; tighten if the service is ever exposed
        # directly to browsers.
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "status": exc.status_code},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled breach-intel error", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "status": 500},
        )

    app.include_router(router)
    return app
