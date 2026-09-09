"""Health-checked Microsoft Sentinel ingestion service."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException

from sentinel_adapter.checkpoint import PostgresSentinelCheckpointStore
from sentinel_adapter.connector import SentinelLogAnalyticsConnector
from shared.db.postgres import PostgresClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SentinelServiceConfig:
    workspace_id: str
    kafka_bootstrap: str
    postgres_dsn: str
    connector_id: str = "sentinel-default"
    poll_interval_seconds: int = 30
    overlap_seconds: int = 60
    subscription_id: str = ""
    resource_group: str = ""
    workspace_name: str = ""

    @classmethod
    def from_env(cls) -> "SentinelServiceConfig":
        workspace_id = os.environ.get("SENTINEL_WORKSPACE_ID", "").strip()
        postgres_dsn = os.environ.get("POSTGRES_DSN", "").strip()
        if not workspace_id:
            raise RuntimeError("SENTINEL_WORKSPACE_ID is required")
        if not postgres_dsn:
            raise RuntimeError("POSTGRES_DSN is required")
        return cls(
            workspace_id=workspace_id,
            kafka_bootstrap=os.environ.get(
                "KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"
            ),
            postgres_dsn=postgres_dsn,
            connector_id=os.environ.get("SENTINEL_CONNECTOR_ID", "sentinel-default"),
            poll_interval_seconds=int(
                os.environ.get("SENTINEL_POLL_INTERVAL_SECONDS", "30")
            ),
            overlap_seconds=int(
                os.environ.get("SENTINEL_OVERLAP_SECONDS", "60")
            ),
            subscription_id=os.environ.get("SENTINEL_SUBSCRIPTION_ID", ""),
            resource_group=os.environ.get("SENTINEL_RESOURCE_GROUP", ""),
            workspace_name=os.environ.get("SENTINEL_WORKSPACE_NAME", ""),
        )


class SentinelRuntime:
    def __init__(self) -> None:
        self.db: PostgresClient | None = None
        self.credential: Any | None = None
        self.connector: SentinelLogAnalyticsConnector | None = None
        self.task: asyncio.Task[None] | None = None


runtime = SentinelRuntime()


@asynccontextmanager
async def lifespan(_: FastAPI):
    config = SentinelServiceConfig.from_env()

    from azure.identity import DefaultAzureCredential

    runtime.db = PostgresClient(dsn=config.postgres_dsn, min_size=1, max_size=5)
    await runtime.db.connect()
    runtime.credential = DefaultAzureCredential()
    runtime.connector = SentinelLogAnalyticsConnector(
        workspace_id=config.workspace_id,
        credential=runtime.credential,
        kafka_bootstrap=config.kafka_bootstrap,
        poll_interval=config.poll_interval_seconds,
        connector_id=config.connector_id,
        checkpoint_store=PostgresSentinelCheckpointStore(runtime.db),
        overlap_seconds=config.overlap_seconds,
        subscription_id=config.subscription_id,
        resource_group=config.resource_group,
        workspace_name=config.workspace_name,
    )
    runtime.task = asyncio.create_task(
        runtime.connector.subscribe(), name="sentinel-log-analytics-poller"
    )
    logger.info("Sentinel ingestion service started for workspace %s", config.workspace_id)

    try:
        yield
    finally:
        if runtime.connector is not None:
            runtime.connector.stop()
        if runtime.task is not None:
            runtime.task.cancel()
            with suppress(asyncio.CancelledError):
                await runtime.task
        if runtime.connector is not None:
            runtime.connector.close()
        if runtime.credential is not None and hasattr(runtime.credential, "close"):
            runtime.credential.close()
        if runtime.db is not None:
            await runtime.db.close()


app = FastAPI(
    title="ALUSKORT Sentinel Adapter",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-adapter"}


@app.get("/ready")
async def ready() -> dict[str, str | None]:
    connector = runtime.connector
    task = runtime.task
    if connector is None or task is None or task.done() or not connector._running:
        raise HTTPException(status_code=503, detail="Sentinel poller is not running")
    if runtime.db is None or not await runtime.db.health_check():
        raise HTTPException(status_code=503, detail="Postgres is unavailable")
    if connector.last_error:
        raise HTTPException(
            status_code=503,
            detail=f"Sentinel polling is failing: {connector.last_error}",
        )
    if connector.last_success_at is None:
        raise HTTPException(
            status_code=503,
            detail="Sentinel poller has not completed its initial query",
        )
    return {
        "status": "ready",
        "last_success_at": connector.last_success_at,
        "last_error": connector.last_error,
    }
