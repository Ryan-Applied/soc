"""Approval queue routes — Story 17-5.

Page showing all AWAITING_HUMAN investigations + approve/reject actions.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.approval_store import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    record_approval_decision,
)
from services.dashboard.deps import get_db, get_repo
from shared.schemas.investigation import InvestigationState

logger = logging.getLogger(__name__)

router = APIRouter()


async def _fetch_awaiting_investigations() -> list[dict[str, Any]]:
    """Fetch all investigations in AWAITING_HUMAN state."""
    db = get_db()
    if db is None:
        return []

    rows = await db.fetch_many(
        """
        SELECT investigation_id, alert_id, tenant_id, state,
               graph_state->>'severity' AS severity,
               graph_state->>'classification' AS classification,
               updated_at
        FROM investigation_state
        WHERE state = $1
        ORDER BY
            CASE graph_state->>'severity'
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            updated_at ASC
        """,
        InvestigationState.AWAITING_HUMAN.value,
    )
    return [dict(r) for r in rows]


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request) -> HTMLResponse:
    """Render the approval queue page."""
    try:
        investigations = await _fetch_awaiting_investigations()
    except Exception:
        investigations = []

    return templates.TemplateResponse(
        request,
        "approvals/queue.html",
        {
            "investigations": investigations,
        },
    )


@router.get("/api/approvals/{investigation_id}/detail", response_class=HTMLResponse)
async def approval_detail_partial(request: Request, investigation_id: str) -> HTMLResponse:
    """Return an HTML fragment with full investigation details for inline expansion."""
    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return templates.TemplateResponse(
        request,
        "approvals/detail_partial.html",
        {"inv": state},
    )


@router.post("/api/investigations/{investigation_id}/approve")
async def approve_investigation(
    request: Request, investigation_id: str
) -> dict[str, str]:
    """Approve an investigation — transition to RESPONDING."""
    db = get_db()
    if db is not None and hasattr(db, "transaction"):
        try:
            state = await record_approval_decision(
                db,
                investigation_id=investigation_id,
                approved=True,
                actor_id=getattr(request.state, "user_id", "unknown"),
                actor_role=getattr(request.state, "user_role", "unknown"),
            )
        except ApprovalNotFoundError:
            raise HTTPException(status_code=404, detail="Investigation not found")
        except ApprovalConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Investigation is in state {exc}, not awaiting_human",
            )
        return {"status": "approved", "new_state": state.state.value}

    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if state.state != InvestigationState.AWAITING_HUMAN:
        raise HTTPException(
            status_code=409,
            detail=f"Investigation is in state {state.state.value}, not awaiting_human",
        )

    await repo.transition(
        state,
        InvestigationState.RESPONDING,
        agent="dashboard_analyst",
        action="approval.granted",
        details={
            "source": "dashboard",
            "actor_id": getattr(request.state, "user_id", "unknown"),
            "actor_role": getattr(request.state, "user_role", "unknown"),
        },
    )

    return {"status": "approved", "new_state": "responding"}


@router.post("/api/investigations/{investigation_id}/reject")
async def reject_investigation(
    request: Request, investigation_id: str
) -> dict[str, str]:
    """Reject an investigation — transition to CLOSED."""
    db = get_db()
    if db is not None and hasattr(db, "transaction"):
        try:
            state = await record_approval_decision(
                db,
                investigation_id=investigation_id,
                approved=False,
                actor_id=getattr(request.state, "user_id", "unknown"),
                actor_role=getattr(request.state, "user_role", "unknown"),
            )
        except ApprovalNotFoundError:
            raise HTTPException(status_code=404, detail="Investigation not found")
        except ApprovalConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Investigation is in state {exc}, not awaiting_human",
            )
        return {"status": "rejected", "new_state": state.state.value}

    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if state.state != InvestigationState.AWAITING_HUMAN:
        raise HTTPException(
            status_code=409,
            detail=f"Investigation is in state {state.state.value}, not awaiting_human",
        )

    await repo.transition(
        state,
        InvestigationState.CLOSED,
        agent="dashboard_analyst",
        action="approval.denied",
        details={
            "source": "dashboard",
            "actor_id": getattr(request.state, "user_id", "unknown"),
            "actor_role": getattr(request.state, "user_role", "unknown"),
        },
    )

    return {"status": "rejected", "new_state": "closed"}
