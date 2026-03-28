"""Analyst Feedback routes — FR-CSM-004.

Allows SOC analysts to submit structured feedback on investigation outcomes,
capturing whether the system's classification, severity assessment, and
recommended actions were correct.  Feedback is persisted to
``analyst_feedback`` and emitted as an audit event so it can be used to
improve detection quality over time.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()

_VALID_VERDICTS = frozenset({"correct", "incorrect", "partial"})


@router.post("/api/investigations/{investigation_id}/feedback", status_code=201)
async def submit_feedback(
    investigation_id: str,
    request: Request,
) -> JSONResponse:
    """Submit analyst feedback on a completed investigation.

    FR-CSM-004: Accepts a structured verdict and optional boolean flags for
    severity agreement, classification correctness, and recommended action
    quality.  Persists to ``analyst_feedback`` and emits an audit event.

    Request body (JSON):
        verdict (str): One of "correct", "incorrect", "partial".
        severity_agreement (bool | null): Was the assigned severity correct?
        classification_correct (bool | null): Was the classification correct?
        recommended_action_correct (bool | null): Were recommended actions right?
        free_text (str | null): Free-form analyst commentary.

    Returns HTTP 201 with the created feedback ``id`` on success.
    Returns HTTP 400 if the body is invalid.
    Returns HTTP 404 if the investigation does not exist.
    """
    body: dict[str, Any] = await request.json()

    # --- Input validation ---
    verdict = body.get("verdict", "")
    if verdict not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid verdict '{verdict}'. "
                f"Must be one of: {', '.join(sorted(_VALID_VERDICTS))}."
            ),
        )

    severity_agreement: bool | None = body.get("severity_agreement")
    classification_correct: bool | None = body.get("classification_correct")
    recommended_action_correct: bool | None = body.get("recommended_action_correct")
    free_text: str | None = body.get("free_text") or None

    # Derive analyst_id from request state (set by RBACMiddleware) or body
    analyst_id: str = ""
    if hasattr(request.state, "user") and request.state.user:
        analyst_id = str(request.state.user)
    if not analyst_id:
        analyst_id = body.get("analyst_id", "")
    if not analyst_id:
        raise HTTPException(status_code=400, detail="analyst_id is required")

    db = get_db()

    # --- Demo mode: no live DB available ---
    if db is None:
        import uuid
        feedback_id = str(uuid.uuid4())
        logger.info(
            "Demo mode: feedback %s for investigation %s from analyst %s (verdict=%s)",
            feedback_id, investigation_id, analyst_id, verdict,
        )
        return JSONResponse(
            status_code=201,
            content={
                "id": feedback_id,
                "investigation_id": investigation_id,
                "verdict": verdict,
                "demo": True,
            },
        )

    # --- Verify investigation exists ---
    inv_row = await db.fetch_one(
        "SELECT investigation_id FROM investigation_state WHERE investigation_id = $1",
        investigation_id,
    )
    if inv_row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    # --- Persist feedback ---
    try:
        row = await db.fetch_one(
            """
            INSERT INTO analyst_feedback
                (investigation_id, analyst_id, verdict,
                 severity_agreement, classification_correct,
                 recommended_action_correct, free_text)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id::text
            """,
            investigation_id,
            analyst_id,
            verdict,
            severity_agreement,
            classification_correct,
            recommended_action_correct,
            free_text,
        )
    except Exception as exc:
        logger.error(
            "Failed to insert analyst_feedback for investigation %s: %s",
            investigation_id, exc,
        )
        raise HTTPException(status_code=500, detail="Failed to save feedback")

    feedback_id: str = row["id"] if row else ""

    # --- Audit event ---
    _emit_feedback_audit(
        db=db,
        investigation_id=investigation_id,
        analyst_id=analyst_id,
        verdict=verdict,
        feedback_id=feedback_id,
    )

    return JSONResponse(
        status_code=201,
        content={
            "id": feedback_id,
            "investigation_id": investigation_id,
            "verdict": verdict,
        },
    )


def _emit_feedback_audit(
    *,
    db: Any,
    investigation_id: str,
    analyst_id: str,
    verdict: str,
    feedback_id: str,
) -> None:
    """Insert an audit record for the submitted feedback (fire-and-forget).

    Uses the same direct-DB pattern as approvals.py since the dashboard
    does not hold a live AuditProducer; this keeps the audit trail
    consistent with other dashboard routes.
    """
    import asyncio

    async def _insert() -> None:
        try:
            await db.execute(
                """
                INSERT INTO audit_records
                    (audit_id, tenant_id, event_type, event_category,
                     investigation_id, payload, timestamp)
                VALUES (gen_random_uuid()::text, 'system',
                        $1, 'action', $2, $3::jsonb, NOW())
                """,
                "analyst.feedback.submitted",
                investigation_id,
                f'{{"verdict": "{verdict}", "feedback_id": "{feedback_id}", '
                f'"analyst_id": "{analyst_id}"}}',
            )
        except Exception as exc:
            logger.warning(
                "Feedback audit emit failed for investigation %s: %s",
                investigation_id, exc,
            )

    # Schedule as a background task so it doesn't block the response
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_insert())
    except RuntimeError:
        # If there's no running loop (e.g. in tests), skip silently
        pass
