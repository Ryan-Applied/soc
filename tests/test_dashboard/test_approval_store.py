"""Transactional approval persistence tests."""

from contextlib import asynccontextmanager

import pytest

from services.dashboard.approval_store import (
    ApprovalConflictError,
    record_approval_decision,
)
from shared.schemas.investigation import GraphState, InvestigationState


class FakeDatabase:
    def __init__(self, state: GraphState) -> None:
        self.state = state
        self.executed: list[tuple] = []

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def fetch_one(self, query, *args):
        return {"graph_state": self.state.model_dump()}

    async def execute(self, query, *args):
        self.executed.append((query, args))


@pytest.mark.asyncio
async def test_approved_decision_is_atomic_and_enqueues_sentinel_writeback():
    state = GraphState(
        investigation_id="inv-1",
        alert_id="alert-1",
        tenant_id="tenant-1",
        state=InvestigationState.AWAITING_HUMAN,
        classification="true_positive",
        confidence=0.91,
        source_context={
            "incident_name": "incident-guid",
            "subscription_id": "sub-1",
            "resource_group": "soc-rg",
            "workspace_name": "sentinel-ws",
        },
    )
    db = FakeDatabase(state)

    result = await record_approval_decision(
        db,
        investigation_id="inv-1",
        approved=True,
        actor_id="user-object-id",
        actor_role="senior_analyst",
    )

    assert result.state == InvestigationState.RESPONDING
    sql = "\n".join(call[0] for call in db.executed)
    assert "UPDATE investigation_state" in sql
    assert "INSERT INTO approval_decisions" in sql
    assert "INSERT INTO sentinel_writeback_outbox" in sql
    approval_args = next(
        args for query, args in db.executed if "INSERT INTO approval_decisions" in query
    )
    assert "user-object-id" in approval_args
    assert "senior_analyst" in approval_args


@pytest.mark.asyncio
async def test_rejection_does_not_enqueue_sentinel_writeback():
    state = GraphState(
        investigation_id="inv-2",
        alert_id="alert-2",
        tenant_id="tenant-1",
        state=InvestigationState.AWAITING_HUMAN,
        source_context={"incident_name": "incident-guid"},
    )
    db = FakeDatabase(state)

    result = await record_approval_decision(
        db,
        investigation_id="inv-2",
        approved=False,
        actor_id="user-object-id",
        actor_role="senior_analyst",
    )

    assert result.state == InvestigationState.CLOSED
    assert not any(
        "sentinel_writeback_outbox" in query for query, _ in db.executed
    )


@pytest.mark.asyncio
async def test_non_pending_investigation_cannot_be_decided_twice():
    state = GraphState(
        investigation_id="inv-3",
        state=InvestigationState.CLOSED,
    )
    db = FakeDatabase(state)

    with pytest.raises(ApprovalConflictError):
        await record_approval_decision(
            db,
            investigation_id="inv-3",
            approved=True,
            actor_id="user-object-id",
            actor_role="senior_analyst",
        )
