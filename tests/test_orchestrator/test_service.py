"""Tests for the Kafka-facing orchestrator service contract."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestrator.service import OrchestratorService
from shared.schemas.investigation import GraphState, InvestigationState


@pytest.mark.asyncio
@patch("orchestrator.service.Producer")
@patch("orchestrator.service.Consumer")
async def test_process_message_preserves_source_context(consumer_cls, producer_cls):
    graph = AsyncMock()
    graph.run.return_value = GraphState(
        investigation_id="inv-1",
        alert_id="alert-1",
        tenant_id="tenant-1",
        source_context={"incident_name": "incident-guid"},
        state=InvestigationState.AWAITING_HUMAN,
    )
    service = OrchestratorService("kafka:9092", graph)
    payload = {
        "alert_id": "alert-1",
        "tenant_id": "tenant-1",
        "title": "Suspicious login",
        "severity": "high",
        "parsed_entities": {"ips": []},
        "source_context": {
            "workspace_id": "workspace-1",
            "incident_name": "incident-guid",
        },
    }

    result = await service.process_message(json.dumps(payload).encode())

    graph.run.assert_awaited_once_with(
        alert_id="alert-1",
        tenant_id="tenant-1",
        entities={"ips": []},
        alert_title="Suspicious login",
        severity="high",
        source_context={
            "workspace_id": "workspace-1",
            "incident_name": "incident-guid",
        },
    )
    assert result["investigation_id"] == "inv-1"
    assert result["source_context"] == {"incident_name": "incident-guid"}
