"""Sentinel service configuration and health tests."""

import pytest

from sentinel_adapter.service import SentinelServiceConfig, health


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE_ID", "workspace-1")
    monkeypatch.setenv("POSTGRES_DSN", "postgresql://db/aluskort")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    monkeypatch.setenv("SENTINEL_POLL_INTERVAL_SECONDS", "45")

    config = SentinelServiceConfig.from_env()

    assert config.workspace_id == "workspace-1"
    assert config.poll_interval_seconds == 45


def test_config_requires_workspace(monkeypatch):
    monkeypatch.delenv("SENTINEL_WORKSPACE_ID", raising=False)
    monkeypatch.setenv("POSTGRES_DSN", "postgresql://db/aluskort")
    with pytest.raises(RuntimeError, match="SENTINEL_WORKSPACE_ID"):
        SentinelServiceConfig.from_env()


@pytest.mark.asyncio
async def test_liveness_endpoint():
    assert await health() == {"status": "ok", "service": "sentinel-adapter"}
