"""Cross-component contract test for the controlled Sentinel pilot path."""

import json
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest

from entity_parser.service import EntityParserService
from orchestrator.graph import InvestigationGraph
from sentinel_adapter.adapter import SentinelAdapter
from services.dashboard.approval_store import record_approval_decision
from shared.schemas.investigation import InvestigationState


class MemoryRepository:
    def __init__(self):
        self.states = {}

    async def load(self, investigation_id):
        return self.states.get(investigation_id)

    async def save(self, state):
        self.states[state.investigation_id] = state.model_copy(deep=True)

    async def transition(self, state, new_state, agent, action, **kwargs):
        state.state = new_state
        state.decision_chain.append({"agent": agent, "action": action})
        await self.save(state)
        return state


class PassAgent:
    async def execute(self, state):
        return state


class AwaitingApprovalReasoner:
    async def execute(self, state):
        state.classification = "true_positive"
        state.confidence = 0.93
        state.recommended_actions = [{
            "action": "isolate_endpoint", "target": "host-1", "tier": 2,
        }]
        state.requires_human_approval = True
        state.state = InvestigationState.AWAITING_HUMAN
        return state


class ApprovalDatabase:
    def __init__(self, state):
        self.state = state
        self.executed = []

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def fetch_one(self, query, *args):
        return {"graph_state": self.state.model_dump()}

    async def execute(self, query, *args):
        self.executed.append((query, args))


@pytest.mark.asyncio
async def test_sentinel_alert_reaches_idempotent_writeback_outbox():
    raw = {
        "SystemAlertId": "sentinel-alert-1",
        "TimeGenerated": "2026-08-20T04:00:00Z",
        "AlertName": "Suspicious sign-in",
        "Description": "Impossible travel detected",
        "Severity": "High",
        "Entities": "[]",
        "TenantId": "tenant-1",
        "IncidentName": "incident-guid",
        "IncidentNumber": 42,
        "_aluskort_connector_id": "sentinel-prod",
        "_aluskort_workspace_id": "workspace-guid",
        "_aluskort_subscription_id": "subscription-guid",
        "_aluskort_resource_group": "soc-rg",
        "_aluskort_workspace_name": "sentinel-ws",
    }
    canonical = SentinelAdapter().to_canonical(raw)
    assert canonical is not None

    with patch("entity_parser.service.Consumer"), patch("entity_parser.service.Producer"):
        normalized = EntityParserService("kafka:9092").process_message(
            json.dumps(canonical.model_dump()).encode()
        )

    repo = MemoryRepository()
    graph = InvestigationGraph(
        repository=repo,
        ioc_extractor=PassAgent(),
        context_enricher=PassAgent(),
        ctem_correlator=PassAgent(),
        atlas_mapper=PassAgent(),
        reasoning_agent=AwaitingApprovalReasoner(),
        response_agent=PassAgent(),
    )
    state = await graph.run(
        alert_id=normalized["alert_id"],
        tenant_id=normalized["tenant_id"],
        entities=normalized["parsed_entities"],
        alert_title=normalized["title"],
        severity=normalized["severity"],
        source_context=normalized["source_context"],
    )
    assert state.state == InvestigationState.AWAITING_HUMAN

    approval_db = ApprovalDatabase(state)
    approved = await record_approval_decision(
        approval_db,
        investigation_id=state.investigation_id,
        approved=True,
        actor_id="entra-user-object-id",
        actor_role="senior_analyst",
    )
    assert approved.state == InvestigationState.RESPONDING

    outbox_args = next(
        args
        for query, args in approval_db.executed
        if "INSERT INTO sentinel_writeback_outbox" in query
    )
    payload = json.loads(outbox_args[-1])
    assert payload["incident_name"] == "incident-guid"
    assert payload["subscription_id"] == "subscription-guid"
    assert payload["resource_group"] == "soc-rg"
    assert payload["workspace_name"] == "sentinel-ws"
    assert payload["tags"] == ["ALUSKORT-Investigated"]
    assert outbox_args[-2] == (
        f"sentinel-investigation-summary:{state.investigation_id}"
    )
