"""Unit tests for ElasticConnector — Story 16-2.

3 tests: polling calls, Kafka publish, retry on failure.
"""

from __future__ import annotations

import asyncio
import json
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from elastic_adapter.connector import ElasticConnector, _canonical_to_bytes
from elastic_adapter.adapter import ElasticAdapter


def _make_mock_aiohttp(response_json: dict):
    """Create a mock aiohttp module with ClientSession that returns given JSON."""
    mock_response = AsyncMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = AsyncMock(return_value=response_json)
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.post = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_mod = ModuleType("aiohttp")
    mock_mod.ClientSession = MagicMock(return_value=mock_session)  # type: ignore[attr-defined]

    return mock_mod, mock_session


class TestCanonicalToBytes:
    """Test the serialisation helper."""

    def test_valid_event_returns_key_value(self):
        adapter = ElasticAdapter()
        raw = {
            "@timestamp": "2026-02-14T10:00:00Z",
            "signal": {
                "rule": {
                    "id": "rule-1",
                    "name": "Test",
                    "description": "test",
                    "severity": "high",
                },
            },
            "kibana": {
                "alert": {"rule": {"parameters": {"threat": [
                    {"tactic": {"name": "Execution"}, "technique": [{"id": "T1059"}]},
                ]}}},
            },
            "host": {"name": "h1"},
        }
        result = _canonical_to_bytes(adapter, raw)
        assert result is not None
        key, value = result
        assert key == b"rule-1"
        parsed = json.loads(value)
        assert parsed["source"] == "elastic"

    def test_heartbeat_returns_none(self):
        adapter = ElasticAdapter()
        raw = {
            "@timestamp": "2026-02-14T10:00:00Z",
            "signal": {"rule": {"id": "r1", "name": "Heartbeat"}},
        }
        assert _canonical_to_bytes(adapter, raw) is None


class TestElasticConnectorPolling:
    """Test the polling mechanism."""

    @pytest.mark.asyncio
    async def test_poll_once_calls_elasticsearch(self):
        """_poll_once sends a POST to .siem-signals-* index."""
        connector = ElasticConnector.__new__(ElasticConnector)
        connector.es_host = "http://es:9200"
        connector.es_api_key = "test-key"
        connector.adapter = ElasticAdapter()
        connector.producer = MagicMock()
        connector._last_poll_ts = None

        mock_mod, mock_session = _make_mock_aiohttp({"hits": {"hits": []}})
        with patch.dict(sys.modules, {"aiohttp": mock_mod}):
            await connector._poll_once()

        mock_session.post.assert_called_once()
        call_url = mock_session.post.call_args[0][0]
        assert ".siem-signals-*/_search" in call_url

    @pytest.mark.asyncio
    async def test_poll_publishes_to_kafka(self):
        """Valid hits are published to the alerts.raw topic."""
        connector = ElasticConnector.__new__(ElasticConnector)
        connector.es_host = "http://es:9200"
        connector.es_api_key = "test-key"
        connector.adapter = ElasticAdapter()
        connector.producer = MagicMock()
        connector._last_poll_ts = None

        hit = {
            "_source": {
                "@timestamp": "2026-02-14T10:00:00Z",
                "signal": {
                    "rule": {"id": "r1", "name": "Test", "description": "d", "severity": "high"},
                },
                "kibana": {"alert": {"rule": {"parameters": {"threat": [
                    {"tactic": {"name": "Execution"}, "technique": [{"id": "T1059"}]},
                ]}}}},
                "host": {"name": "h1"},
            }
        }

        mock_mod, mock_session = _make_mock_aiohttp({"hits": {"hits": [hit]}})
        with patch.dict(sys.modules, {"aiohttp": mock_mod}):
            await connector._poll_once()

        connector.producer.produce.assert_called_once()
        assert connector.producer.produce.call_args[1]["topic"] == "alerts.raw"

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """retry_with_backoff retries on transient failures."""
        call_count = 0

        async def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("transient")
            return "ok"

        from sentinel_adapter.connector import retry_with_backoff

        result = await retry_with_backoff(flaky, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 3
