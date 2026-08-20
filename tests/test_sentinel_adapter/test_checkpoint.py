"""Tests for durable Sentinel polling state."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from sentinel_adapter.checkpoint import PostgresSentinelCheckpointStore


@pytest.fixture
def db():
    client = AsyncMock()
    client.fetch_one = AsyncMock(return_value=None)
    client.execute = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_load_watermark_serializes_datetime(db):
    db.fetch_one.return_value = {
        "watermark": datetime(2026, 8, 20, 1, 2, 3, tzinfo=timezone.utc)
    }
    store = PostgresSentinelCheckpointStore(db)

    assert await store.load_watermark("sentinel-a") == "2026-08-20T01:02:03+00:00"


@pytest.mark.asyncio
async def test_missing_watermark_returns_none(db):
    store = PostgresSentinelCheckpointStore(db)
    assert await store.load_watermark("sentinel-a") is None


@pytest.mark.asyncio
async def test_processed_lookup_is_scoped_by_connector(db):
    db.fetch_one.return_value = {"processed": 1}
    store = PostgresSentinelCheckpointStore(db)

    assert await store.is_processed("sentinel-a", "alert-1") is True
    assert db.fetch_one.call_args.args[1:] == ("sentinel-a", "alert-1")


@pytest.mark.asyncio
async def test_mark_processed_and_save_watermark(db):
    store = PostgresSentinelCheckpointStore(db)
    await store.mark_processed("sentinel-a", "alert-1", "2026-08-20T01:02:03Z")
    await store.save_watermark("sentinel-a", "2026-08-20T01:02:03Z")

    assert db.execute.await_count == 2
    assert "sentinel_ingested_alerts" in db.execute.await_args_list[0].args[0]
    assert "sentinel_ingestion_checkpoints" in db.execute.await_args_list[1].args[0]
