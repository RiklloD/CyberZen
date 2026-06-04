"""
Sentinel Sandbox Manager — FastAPI application.

Endpoints:
  GET  /health              — liveness probe
  POST /validate            — run exploit validation for a finding
  POST /poc                 — generate PoC only (dry_run, no live requests)
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .executor import run_validation
from .models import SandboxMode, ValidationRequest, ValidationResult

app = FastAPI(
    title="Sentinel Sandbox Manager",
    version="0.2.0",
    description=(
        "HTTP-based exploit execution engine. "
        "Receives ValidationRequests from Convex, fires real HTTP exploit attempts "
        "against a target environment, and returns ValidationResults with PoC artifacts."
    ),
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {
        "service": "sentinel-sandbox-manager",
        "status": "ok",
        "version": app.version,
        "capabilities": ["http_probe", "dry_run"],
    }


# ── Validate ──────────────────────────────────────────────────────────────────

@app.post("/validate", response_model=ValidationResult)
async def validate(req: ValidationRequest) -> ValidationResult:
    """
    Run a full exploit validation for a finding.

    - If `target_base_url` is provided, fires real HTTP requests (http_probe mode).
    - If `target_base_url` is absent, generates PoC only (dry_run mode).
    - Results are posted back here; Convex polls or receives a webhook.
    """
    result = await run_validation(req)
    return result


# ── PoC only ──────────────────────────────────────────────────────────────────

@app.post("/poc", response_model=ValidationResult)
async def generate_poc(req: ValidationRequest) -> ValidationResult:
    """
    Force dry_run mode — generate PoC artifacts without executing live requests.
    Useful for findings against production targets where live probing is prohibited.
    """
    dry_req = req.model_copy(update={"sandbox_mode": SandboxMode.DRY_RUN})
    result = await run_validation(dry_req)
    return result


# ── Error handling ────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_error_handler(request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"detail": f"Sandbox internal error: {exc}"},
    )
