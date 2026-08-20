"""Unit tests for Splunk connectors — Stories 16-5 & 16-6.

4 tests for HEC connector (valid event, heartbeat dropped, bad token, Kafka publish).
3 tests for Saved-Search connector (polling, Kafka publish, retry).
"""

from __future__ import annotations

import asyncio
import json
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from splunk_adapter.connector import (
    SplunkHECConnector,
    SplunkSavedSearchConnector,
    _canonical_to_bytes,
)
from splunk_adapter.adapter import SplunkAdapter


def _make_mock_aiohttp(response_json: dict):
    """Create a mock aiohttp module with ClientSession that returns given JSON."""
    mock_response = AsyncMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = AsyncMock(return_value=response_json)
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_mod = ModuleType("aiohttp")
    mock_mod.ClientSession = MagicMock(return_value=mock_session)  # type: ignore[attr-defined]

    return mock_mod, mock_session


# =====================================================================
# HEC Connector tests (Story 16-5)
# =====================================================================


class TestSplunkHECConnector:
    """Tests for the HEC webhook receiver."""

    def _make_connector(self) -> SplunkHECConnector:
        connector = SplunkHECConnector.__new__(SplunkHECConnector)
        connector.kafka_bootstrap = "localhost:9092"
        connector.hec_token = "test-token-123"
        connector.port = 8088
        connector.adapter = SplunkAdapter()
        connector.producer = MagicMock()
        connector._app = None
        return connector

    def test_valid_event_accepted(self):
        """Valid HEC POST with correct token returns success."""
        connector = self._make_connector()
        app = connector._build_app()
        client = TestClient(app)

        payload = {
            "event": {
                "event_id": "notable-001",
                "_time": "2026-02-14T10:00:00Z",
                "search_name": "Access - Brute Force Detected",
                "description": "Brute force attempt",
                "urgency": "high",
                "annotations": {
                    "mitre_attack": {
                        "mitre_tactic": ["Credential Access"],
                        "mitre_technique_id": ["T1110"],
                    }
                },
                "src": "10.0.0.99",
                "user": "admin",
            }
        }

        resp = client.post(
            "/services/collector/event",
            json=payload,
            headers={"Authorization": "Splunk test-token-123"},
        )
        assert resp.status_code == 200
        assert resp.json()["text"] == "Success"
        connector.producer.produce.assert_called_once()

    def test_heartbeat_event_dropped(self):
        """Health-check events are silently dropped (no Kafka publish)."""
        connector = self._make_connector()
        app = connector._build_app()
        client = TestClient(app)

        payload = {
            "event": {
                "event_id": "hb-001",
                "_time": "2026-02-14T10:00:00Z",
                "search_name": "Health Check - Forwarders",
                "description": "Forwarder health",
                "urgency": "low",
            }
        }

        resp = client.post(
            "/services/collector/event",
            json=payload,
            headers={"Authorization": "Splunk test-token-123"},
        )
        assert resp.status_code == 200
        connector.producer.produce.assert_not_called()

    def test_bad_token_rejected(self):
        """Incorrect HEC token returns 403."""
        connector = self._make_connector()
        app = connector._build_app()
        client = TestClient(app)

        resp = client.post(
            "/services/collector/event",
            json={"event": {}},
            headers={"Authorization": "Splunk wrong-token"},
        )
        assert resp.status_code == 403

    def test_kafka_publish_has_correct_topic(self):
        """Published messages go to the alerts.raw topic."""
        connector = self._make_connector()
        app = connector._build_app()
        client = TestClient(app)

        payload = {
            "event": {
                "event_id": "n-002",
                "_time": "2026-02-14T10:00:00Z",
                "search_name": "Endpoint - Suspicious Process",
                "description": "Suspicious",
                "urgency": "medium",
                "annotations": {
                    "mitre_attack": {
                        "mitre_tactic": ["Execution"],
                        "mitre_technique_id": ["T1059"],
                    }
                },
                "user": "jdoe",
            }
        }

        client.post(
            "/services/collector/event",
            json=payload,
            headers={"Authorization": "Splunk test-token-123"},
        )
        call_kwargs = connector.producer.produce.call_args[1]
        assert call_kwargs["topic"] == "alerts.raw"


# =====================================================================
# Saved-Search Connector tests (Story 16-6)
# =====================================================================


class TestSplunkSavedSearchConnector:
    """Tests for the polling-based saved-search connector."""

    @pytest.mark.asyncio
    async def test_poll_once_calls_splunk_api(self):
        """_poll_once sends a GET to /services/saved/searches."""
        connector = SplunkSavedSearchConnector.__new__(SplunkSavedSearchConnector)
        connector.splunk_host = "https://splunk:8089"
        connector.splunk_token = "tok"
        connector.adapter = SplunkAdapter()
        connector.producer = MagicMock()
        connector._last_dispatch_time = None

        mock_mod, mock_session = _make_mock_aiohttp({"entry": []})
        with patch.dict(sys.modules, {"aiohttp": mock_mod}):
            await connector._poll_once()

        mock_session.get.assert_called_once()
        call_url = mock_session.get.call_args[0][0]
        assert "/services/saved/searches" in call_url

    @pytest.mark.asyncio
    async def test_poll_publishes_to_kafka(self):
        """Valid saved-search entries are published to Kafka."""
        connector = SplunkSavedSearchConnector.__new__(SplunkSavedSearchConnector)
        connector.splunk_host = "https://splunk:8089"
        connector.splunk_token = "tok"
        connector.adapter = SplunkAdapter()
        connector.producer = MagicMock()
        connector._last_dispatch_time = None

        entry = {
            "name": "Access - Brute Force",
            "content": {
                "event_id": "ss-001",
                "_time": "2026-02-14T10:00:00Z",
                "description": "Brute force",
                "urgency": "high",
                "dispatch.latest_time": "2026-02-14T10:00:00Z",
                "annotations": {
                    "mitre_attack": {
                        "mitre_tactic": ["Credential Access"],
                        "mitre_technique_id": ["T1110"],
                    }
                },
                "src": "10.0.0.1",
            },
        }

        mock_mod, mock_session = _make_mock_aiohttp({"entry": [entry]})
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
            if call_count < 2:
                raise ConnectionError("transient")
            return "ok"

        from sentinel_adapter.connector import retry_with_backoff

        result = await retry_with_backoff(flaky, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 2
