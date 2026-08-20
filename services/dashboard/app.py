"""Dashboard FastAPI application — Story 17-1.

Analyst Investigation Dashboard: lightweight FastAPI + HTMX + Jinja2 web UI
for SOC analysts to view investigations, approve/reject actions, and monitor
system health.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

# Resolve paths relative to this file
_BASE_DIR = Path(__file__).resolve().parent
_TEMPLATE_DIR = _BASE_DIR / "templates"
_STATIC_DIR = _BASE_DIR / "static"

templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# Infrastructure clients — held at module level for cleanup
_pg_client: Any = None
_redis_client: Any = None


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Connect to Postgres and Redis from environment variables on startup."""
    global _pg_client, _redis_client
    from services.dashboard.deps import init_deps

    postgres_dsn = os.environ.get("POSTGRES_DSN", "")
    redis_host = os.environ.get("REDIS_HOST", "")
    production = os.environ.get("APP_ENV", "development").lower() == "production"
    if production and (not postgres_dsn or not redis_host):
        raise RuntimeError("Production dashboard requires Postgres and Redis")

    db = None
    if postgres_dsn:
        try:
            from shared.db.postgres import PostgresClient
            db = PostgresClient(dsn=postgres_dsn)
            await db.connect()
            _pg_client = db
            logger.info("Dashboard connected to Postgres")
        except Exception:
            if production:
                raise
            logger.warning("Dashboard: Postgres connection failed", exc_info=True)

    rc = None
    if redis_host:
        try:
            from shared.db.redis_cache import RedisClient
            rc = RedisClient(host=redis_host)
            await rc.connect()
            _redis_client = rc
            logger.info("Dashboard connected to Redis")
        except Exception:
            if production:
                if _pg_client is not None:
                    await _pg_client.close()
                    _pg_client = None
                raise
            logger.warning("Dashboard: Redis connection failed", exc_info=True)

    init_deps(db, rc)

    yield

    # Cleanup
    if _pg_client is not None:
        try:
            await _pg_client.close()
        except Exception:
            pass
    if _redis_client is not None:
        try:
            await _redis_client.close()
        except Exception:
            pass


app = FastAPI(
    title="ALUSKORT Analyst Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ------------------------------------------------------------------
# Routes — imported after app is created to avoid circular imports
# ------------------------------------------------------------------

from services.dashboard.routes.investigations import router as investigations_router  # noqa: E402
from services.dashboard.routes.investigation_detail import router as detail_router  # noqa: E402
from services.dashboard.routes.timeline import router as timeline_router  # noqa: E402
from services.dashboard.routes.approvals import router as approvals_router  # noqa: E402
from services.dashboard.routes.metrics import router as metrics_router  # noqa: E402
from services.dashboard.routes.connectors import router as connectors_router  # noqa: E402
from services.dashboard.routes.settings import router as settings_router  # noqa: E402
from services.dashboard.routes.test_harness import router as test_harness_router  # noqa: E402
from services.dashboard.routes.ctem import router as ctem_router  # noqa: E402
from services.dashboard.routes.cti import router as cti_router  # noqa: E402
from services.dashboard.routes.adversarial_ai import router as adversarial_ai_router  # noqa: E402
from services.dashboard.routes.shadow_mode import router as shadow_mode_router  # noqa: E402
from services.dashboard.routes.canary import router as canary_router  # noqa: E402
from services.dashboard.routes.fp_patterns import router as fp_patterns_router  # noqa: E402
from services.dashboard.routes.audit_trail import router as audit_trail_router  # noqa: E402
from services.dashboard.routes.playbooks import router as playbooks_router  # noqa: E402
from services.dashboard.routes.batch_jobs import router as batch_jobs_router  # noqa: E402
from services.dashboard.routes.users import router as users_router  # noqa: E402
from services.dashboard.routes.llm_health import router as llm_health_router  # noqa: E402
from services.dashboard.routes.ciso import router as ciso_router  # noqa: E402
from services.dashboard.routes.feedback import router as feedback_router  # noqa: E402
from services.dashboard.middleware.auth import RBACMiddleware  # noqa: E402
from services.dashboard.ws import websocket_investigations  # noqa: E402

app.add_middleware(RBACMiddleware)

# WebSocket endpoint — Story 17-7
app.websocket("/ws/investigations")(websocket_investigations)

app.include_router(investigations_router)
app.include_router(detail_router)
app.include_router(timeline_router)
app.include_router(approvals_router)
app.include_router(metrics_router)
app.include_router(connectors_router)
app.include_router(settings_router)
app.include_router(test_harness_router)
app.include_router(ctem_router)
app.include_router(cti_router)
app.include_router(adversarial_ai_router)
app.include_router(shadow_mode_router)
app.include_router(canary_router)
app.include_router(fp_patterns_router)
app.include_router(audit_trail_router)
app.include_router(playbooks_router)
app.include_router(batch_jobs_router)
app.include_router(users_router)
app.include_router(llm_health_router)
app.include_router(ciso_router)
app.include_router(feedback_router)


# ------------------------------------------------------------------
# Root + health
# ------------------------------------------------------------------


@app.get("/")
async def index() -> RedirectResponse:
    """Landing page redirects to investigation list."""
    return RedirectResponse(url="/investigations", status_code=302)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "dashboard"}


def init_app(postgres_client: Any, redis_client: Any = None) -> FastAPI:
    """Initialise dependencies and return the app."""
    from services.dashboard.deps import init_deps

    init_deps(postgres_client, redis_client)
    return app
