"""Durable checkpoints and deduplication for Sentinel polling."""

from __future__ import annotations

from typing import Any, Protocol


class SentinelCheckpointStore(Protocol):
    """Persistence contract used by the Log Analytics connector."""

    async def load_watermark(self, connector_id: str) -> str | None: ...

    async def is_processed(self, connector_id: str, alert_id: str) -> bool: ...

    async def mark_processed(
        self, connector_id: str, alert_id: str, time_generated: str,
    ) -> None: ...

    async def save_watermark(self, connector_id: str, watermark: str) -> None: ...


class PostgresSentinelCheckpointStore:
    """Postgres implementation of the Sentinel ingestion state contract."""

    def __init__(self, postgres_client: Any) -> None:
        self._db = postgres_client

    async def load_watermark(self, connector_id: str) -> str | None:
        row = await self._db.fetch_one(
            "SELECT watermark FROM sentinel_ingestion_checkpoints "
            "WHERE connector_id = $1",
            connector_id,
        )
        if row is None or row.get("watermark") is None:
            return None
        watermark = row["watermark"]
        return watermark.isoformat() if hasattr(watermark, "isoformat") else str(watermark)

    async def is_processed(self, connector_id: str, alert_id: str) -> bool:
        row = await self._db.fetch_one(
            "SELECT 1 AS processed FROM sentinel_ingested_alerts "
            "WHERE connector_id = $1 AND alert_id = $2",
            connector_id,
            alert_id,
        )
        return row is not None

    async def mark_processed(
        self, connector_id: str, alert_id: str, time_generated: str,
    ) -> None:
        await self._db.execute(
            """
            INSERT INTO sentinel_ingested_alerts
                (connector_id, alert_id, time_generated)
            VALUES ($1, $2, $3::timestamptz)
            ON CONFLICT (connector_id, alert_id) DO NOTHING
            """,
            connector_id,
            alert_id,
            time_generated,
        )

    async def save_watermark(self, connector_id: str, watermark: str) -> None:
        await self._db.execute(
            """
            INSERT INTO sentinel_ingestion_checkpoints
                (connector_id, watermark, updated_at)
            VALUES ($1, $2::timestamptz, NOW())
            ON CONFLICT (connector_id) DO UPDATE SET
                watermark = EXCLUDED.watermark,
                updated_at = NOW()
            """,
            connector_id,
            watermark,
        )
