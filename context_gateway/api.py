"""Context Gateway FastAPI service — serves LLM completion requests.

Exposes the ContextGateway pipeline (sanitise, redact, call, validate,
deanonymise) as an HTTP API for use by other ALUSKORT services.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---- request / response schemas -------------------------------------------

class CompletionRequest(BaseModel):
    agent_id: str
    task_type: str
    system_prompt: str
    user_content: str
    output_schema: dict[str, Any] | None = None
    tenant_id: str = "default"
    use_extended_thinking: bool = False


class CompletionResponse(BaseModel):
    content: str
    model_id: str
    tokens_used: int
    valid: bool
    validation_errors: list[str] = Field(default_factory=list)
    quarantined_ids: list[str] = Field(default_factory=list)
    injection_detections: list[str] = Field(default_factory=list)
    cost_usd: float = 0.0
    latency_ms: float = 0.0


class SpendResponse(BaseModel):
    monthly_total: float
    call_count: int
    by_model: dict[str, float]


# ---- app state (populated at startup) -------------------------------------

_gateway: Any = None
_spend_guard: Any = None
_db: Any = None
_ready = False


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize gateway dependencies on startup."""
    global _gateway, _spend_guard, _db, _ready

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is required")

    from context_gateway.anthropic_client import AluskortAnthropicClient
    from context_gateway.gateway import ContextGateway
    from context_gateway.spend_guard import SpendGuard

    client = AluskortAnthropicClient(api_key=api_key)
    _spend_guard = SpendGuard()

    # Optionally load taxonomy IDs from Postgres
    known_ids: set[str] = set()
    taxonomy_version = ""
    postgres_dsn = os.environ.get("POSTGRES_DSN", "")
    if postgres_dsn:
        try:
            from shared.db.postgres import PostgresClient
            _db = PostgresClient(dsn=postgres_dsn)
            await _db.connect()
            known_ids = await _db.get_technique_ids()
            taxonomy_version = await _db.get_taxonomy_version()
            logger.info(
                "Loaded %d taxonomy IDs (version=%s)", len(known_ids), taxonomy_version,
            )
        except Exception:
            logger.warning("Failed to load taxonomy from Postgres", exc_info=True)
            _db = None

    _gateway = ContextGateway(
        client=client,
        spend_guard=_spend_guard,
        known_technique_ids=known_ids if known_ids else None,
        taxonomy_version=taxonomy_version,
    )
    _ready = True
    logger.info("Context Gateway initialized")

    yield

    # Cleanup
    _ready = False
    await client.close()
    if _db is not None:
        await _db.close()
        _db = None


app = FastAPI(
    title="ALUSKORT Context Gateway",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "context-gateway"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if not _ready:
        raise HTTPException(503, "Context Gateway is not ready")
    return {"status": "ready", "service": "context-gateway"}


@app.post("/v1/complete", response_model=CompletionResponse)
async def complete(req: CompletionRequest) -> CompletionResponse:
    """Run the full gateway pipeline: sanitise → redact → LLM → validate."""
    if _gateway is None:
        raise HTTPException(503, "Gateway not initialized")

    from context_gateway.gateway import GatewayRequest

    gw_request = GatewayRequest(
        agent_id=req.agent_id,
        task_type=req.task_type,
        system_prompt=req.system_prompt,
        user_content=req.user_content,
        output_schema=req.output_schema,
        tenant_id=req.tenant_id,
        use_extended_thinking=req.use_extended_thinking,
    )

    try:
        resp = await _gateway.complete(gw_request)
    except Exception as exc:
        logger.error("Gateway completion failed: %s", exc, exc_info=True)
        raise HTTPException(502, f"LLM call failed: {exc}")

    return CompletionResponse(
        content=resp.content,
        model_id=resp.model_id,
        tokens_used=resp.tokens_used,
        valid=resp.valid,
        validation_errors=resp.validation_errors,
        quarantined_ids=resp.quarantined_ids,
        injection_detections=resp.injection_detections,
        cost_usd=resp.metrics.cost_usd if resp.metrics else 0.0,
        latency_ms=resp.metrics.latency_ms if resp.metrics else 0.0,
    )


@app.get("/v1/spend", response_model=SpendResponse)
async def spend_status() -> SpendResponse:
    """Return current spend tracking data."""
    if _spend_guard is None:
        raise HTTPException(503, "Spend guard not initialized")
    return SpendResponse(
        monthly_total=_spend_guard.monthly_total,
        call_count=_spend_guard.call_count,
        by_model=_spend_guard.total_by_model(),
    )
