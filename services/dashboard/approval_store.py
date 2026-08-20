"""Transactional persistence for analyst approval decisions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from shared.schemas.investigation import GraphState, InvestigationState


class ApprovalNotFoundError(Exception):
    pass


class ApprovalConflictError(Exception):
    pass


async def record_approval_decision(
    db: Any,
    *,
    investigation_id: str,
    approved: bool,
    actor_id: str,
    actor_role: str,
    reason: str = "",
) -> GraphState:
    """Lock an investigation and atomically persist its decision and outbox work."""
    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT graph_state
            FROM investigation_state
            WHERE investigation_id = $1
            FOR UPDATE
            """,
            investigation_id,
        )
        if row is None:
            raise ApprovalNotFoundError(investigation_id)

        raw_state = row["graph_state"]
        state = GraphState.model_validate(
            raw_state if isinstance(raw_state, dict) else json.loads(raw_state)
        )
        if state.state != InvestigationState.AWAITING_HUMAN:
            raise ApprovalConflictError(state.state.value)

        decision = "approved" if approved else "rejected"
        target_state = (
            InvestigationState.RESPONDING if approved else InvestigationState.CLOSED
        )
        decided_at = datetime.now(timezone.utc).isoformat()
        state.state = target_state
        action = "approval.granted" if approved else "approval.denied"
        state.decision_chain.append({
            "agent": actor_id,
            "action": action,
            "timestamp": decided_at,
            "details": {
                "source": "dashboard",
                "actor_id": actor_id,
                "actor_role": actor_role,
                "reason": reason,
            },
        })

        await tx.execute(
            """
            UPDATE investigation_state
            SET state = $2, graph_state = $3::jsonb, updated_at = NOW()
            WHERE investigation_id = $1
            """,
            investigation_id,
            target_state.value,
            state.model_dump_json(),
        )

        approval_id = uuid4()
        await tx.execute(
            """
            INSERT INTO approval_decisions
                (approval_id, investigation_id, tenant_id, decision,
                 actor_id, actor_role, reason, source_context)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
            """,
            approval_id,
            investigation_id,
            state.tenant_id,
            decision,
            actor_id,
            actor_role,
            reason or None,
            json.dumps(state.source_context),
        )

        incident_name = state.source_context.get("incident_name")
        if approved and incident_name:
            payload = {
                "subscription_id": state.source_context.get("subscription_id"),
                "resource_group": state.source_context.get("resource_group"),
                "workspace_name": state.source_context.get("workspace_name"),
                "incident_name": incident_name,
                "incident_number": state.source_context.get("incident_number"),
                "comment": (
                    f"ALUSKORT investigation {investigation_id}: "
                    f"classification={state.classification or 'undetermined'}, "
                    f"confidence={state.confidence:.2f}, approved_by={actor_id}."
                ),
                "tags": ["ALUSKORT-Investigated"],
            }
            await tx.execute(
                """
                INSERT INTO sentinel_writeback_outbox
                    (outbox_id, approval_id, investigation_id, tenant_id,
                     idempotency_key, payload)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                """,
                uuid4(),
                approval_id,
                investigation_id,
                state.tenant_id,
                f"sentinel-investigation-summary:{investigation_id}",
                json.dumps(payload),
            )

        return state
