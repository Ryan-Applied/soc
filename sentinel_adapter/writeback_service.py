"""Worker service that drains approved investigation updates into Sentinel."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException

from sentinel_adapter.writeback import (
    PermanentWritebackError,
    PostgresWritebackOutbox,
    SentinelIncidentClient,
)
from shared.db.postgres import PostgresClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WritebackConfig:
    postgres_dsn: str
    poll_interval_seconds: int = 10
    batch_size: int = 10

    @classmethod
    def from_env(cls) -> "WritebackConfig":
        dsn = os.environ.get("POSTGRES_DSN", "").strip()
        if not dsn:
            raise RuntimeError("POSTGRES_DSN is required")
        return cls(
            postgres_dsn=dsn,
            poll_interval_seconds=int(
                os.environ.get("SENTINEL_WRITEBACK_POLL_SECONDS", "10")
            ),
            batch_size=int(os.environ.get("SENTINEL_WRITEBACK_BATCH_SIZE", "10")),
        )


class WritebackRuntime:
    def __init__(self) -> None:
        self.db: PostgresClient | None = None
        self.credential: Any = None
        self.outbox: PostgresWritebackOutbox | None = None
        self.client: SentinelIncidentClient | None = None
        self.task: asyncio.Task[None] | None = None
        self.running = False
        self.last_success_at: str | None = None
        self.last_error: str | None = None


runtime = WritebackRuntime()


async def _run_worker(config: WritebackConfig) -> None:
    runtime.running = True
    try:
        while runtime.running:
            assert runtime.outbox is not None
            assert runtime.client is not None
            try:
                items = await runtime.outbox.claim(config.batch_size)
            except Exception as exc:
                runtime.last_error = str(exc)
                logger.error("Failed to claim Sentinel write-back work: %s", exc)
                await asyncio.sleep(config.poll_interval_seconds)
                continue
            for item in items:
                try:
                    await runtime.client.write_investigation_summary(
                        item["payload"], item["idempotency_key"]
                    )
                    await runtime.outbox.complete(item["outbox_id"])
                    runtime.last_success_at = datetime.now(timezone.utc).isoformat()
                    runtime.last_error = None
                except Exception as exc:
                    permanent = isinstance(exc, PermanentWritebackError)
                    await runtime.outbox.fail(
                        item["outbox_id"],
                        str(exc),
                        int(item["attempts"]),
                        permanent=permanent,
                    )
                    runtime.last_error = str(exc)
                    logger.error("Sentinel write-back failed: %s", exc)
            await asyncio.sleep(config.poll_interval_seconds)
    finally:
        runtime.running = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    config = WritebackConfig.from_env()
    from azure.identity import DefaultAzureCredential

    runtime.db = PostgresClient(dsn=config.postgres_dsn, min_size=1, max_size=5)
    await runtime.db.connect()
    runtime.credential = DefaultAzureCredential()
    await asyncio.to_thread(
        runtime.credential.get_token,
        SentinelIncidentClient.ARM_SCOPE,
    )
    runtime.outbox = PostgresWritebackOutbox(runtime.db)
    runtime.client = SentinelIncidentClient(runtime.credential)
    runtime.task = asyncio.create_task(
        _run_worker(config), name="sentinel-writeback-outbox"
    )
    try:
        yield
    finally:
        runtime.running = False
        if runtime.task is not None:
            runtime.task.cancel()
            with suppress(asyncio.CancelledError):
                await runtime.task
        if runtime.credential is not None and hasattr(runtime.credential, "close"):
            runtime.credential.close()
        if runtime.db is not None:
            await runtime.db.close()


app = FastAPI(
    title="ALUSKORT Sentinel Write-back",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-writeback"}


@app.get("/ready")
async def ready() -> dict[str, str | None]:
    if not runtime.running or runtime.task is None or runtime.task.done():
        raise HTTPException(503, "Sentinel write-back worker is not running")
    if runtime.db is None or not await runtime.db.health_check():
        raise HTTPException(503, "Postgres is unavailable")
    return {
        "status": "ready",
        "last_success_at": runtime.last_success_at,
        "last_error": runtime.last_error,
    }
