"""FP Pattern Management routes — governance dashboard for false-positive patterns.

Provides pattern library view, filtering, two-person approval, reaffirmation,
and revocation endpoints with fallback demo data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from atlas_detection.safety_guard import ATLASSafetyGuard
from services.dashboard.app import templates
from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()

EXPIRY_DAYS = 90

# ---------------------------------------------------------------------------
# Demo / fallback data
# ---------------------------------------------------------------------------

_now = datetime(2026, 3, 29, 12, 0, 0, tzinfo=timezone.utc)


def _demo_patterns() -> list[dict[str, Any]]:
    """Return realistic demo FP patterns for fallback display."""
    patterns = [
        {
            "pattern_id": "FP-001",
            "name": "Scheduled backup login noise",
            "description": "Automated backup service account triggers login_anomaly alerts every night during the 02:00-04:00 UTC maintenance window.",
            "rule_family": "login_anomaly",
            "match_criteria": {
                "source": "backup-agent",
                "entity_pattern": "svc-backup-*",
                "time_window": "02:00-04:00 UTC",
            },
            "status": "active",
            "creator": "analyst.chen",
            "approver": "sr.analyst.martinez",
            "approval_date": (_now - timedelta(days=45)).isoformat(),
            "created_date": (_now - timedelta(days=47)).isoformat(),
            "expires_date": (_now - timedelta(days=45) + timedelta(days=EXPIRY_DAYS)).isoformat(),
            "auto_closed_count": 312,
            "precision_score": 99.4,
        },
        {
            "pattern_id": "FP-002",
            "name": "Internal vulnerability scanner traffic",
            "description": "Qualys scanner IP range generates network_scan alerts during weekly scheduled scans on Sundays.",
            "rule_family": "network_scan",
            "match_criteria": {
                "source": "qualys-scanner",
                "entity_pattern": "10.20.30.*",
                "time_window": "Sunday 00:00-06:00 UTC",
            },
            "status": "active",
            "creator": "analyst.johansson",
            "approver": "sr.analyst.martinez",
            "approval_date": (_now - timedelta(days=80)).isoformat(),
            "created_date": (_now - timedelta(days=82)).isoformat(),
            "expires_date": (_now - timedelta(days=80) + timedelta(days=EXPIRY_DAYS)).isoformat(),
            "auto_closed_count": 87,
            "precision_score": 98.7,
        },
        {
            "pattern_id": "FP-003",
            "name": "Dev environment test alerts",
            "description": "CI/CD pipeline in dev-cluster triggers malware_detection on test payloads containing EICAR samples.",
            "rule_family": "malware_detection",
            "match_criteria": {
                "source": "ci-runner",
                "entity_pattern": "dev-cluster-*",
                "time_window": "any",
            },
            "status": "active",
            "creator": "analyst.park",
            "approver": "sr.analyst.okonkwo",
            "approval_date": (_now - timedelta(days=20)).isoformat(),
            "created_date": (_now - timedelta(days=22)).isoformat(),
            "expires_date": (_now - timedelta(days=20) + timedelta(days=EXPIRY_DAYS)).isoformat(),
            "auto_closed_count": 156,
            "precision_score": 100.0,
        },
        {
            "pattern_id": "FP-004",
            "name": "Azure AD sync service logins",
            "description": "Azure AD Connect health agent creates repeated auth_failure alerts due to token refresh cycles.",
            "rule_family": "login_anomaly",
            "match_criteria": {
                "source": "azure-ad-connect",
                "entity_pattern": "svc-aadsync-*",
                "time_window": "any",
            },
            "status": "pending_approval",
            "creator": "analyst.chen",
            "approver": None,
            "approval_date": None,
            "created_date": (_now - timedelta(days=2)).isoformat(),
            "expires_date": None,
            "auto_closed_count": 0,
            "precision_score": 0.0,
        },
        {
            "pattern_id": "FP-005",
            "name": "Printer SNMP broadcast noise",
            "description": "Network printers emit SNMP discovery broadcasts flagged as network_scan by perimeter IDS.",
            "rule_family": "network_scan",
            "match_criteria": {
                "source": "ids-perimeter",
                "entity_pattern": "printer-*",
                "time_window": "any",
            },
            "status": "expired",
            "creator": "analyst.johansson",
            "approver": "sr.analyst.martinez",
            "approval_date": (_now - timedelta(days=95)).isoformat(),
            "created_date": (_now - timedelta(days=97)).isoformat(),
            "expires_date": (_now - timedelta(days=5)).isoformat(),
            "auto_closed_count": 421,
            "precision_score": 97.2,
        },
        {
            "pattern_id": "FP-006",
            "name": "Canary token test fires",
            "description": "Honeypot canary tokens in staging environment trigger data_exfil alerts during quarterly pen-tests.",
            "rule_family": "data_exfiltration",
            "match_criteria": {
                "source": "canary-service",
                "entity_pattern": "staging-canary-*",
                "time_window": "quarterly pen-test windows",
            },
            "status": "active",
            "creator": "analyst.park",
            "approver": "sr.analyst.okonkwo",
            "approval_date": (_now - timedelta(days=60)).isoformat(),
            "created_date": (_now - timedelta(days=62)).isoformat(),
            "expires_date": (_now - timedelta(days=60) + timedelta(days=EXPIRY_DAYS)).isoformat(),
            "auto_closed_count": 24,
            "precision_score": 100.0,
        },
        {
            "pattern_id": "FP-007",
            "name": "Load balancer health check spikes",
            "description": "AWS ALB health checks cause login_anomaly spikes when targets restart during blue-green deploy.",
            "rule_family": "login_anomaly",
            "match_criteria": {
                "source": "aws-alb",
                "entity_pattern": "alb-healthcheck-*",
                "time_window": "deploy windows",
            },
            "status": "pending_approval",
            "creator": "analyst.johansson",
            "approver": None,
            "approval_date": None,
            "created_date": (_now - timedelta(days=1)).isoformat(),
            "expires_date": None,
            "auto_closed_count": 0,
            "precision_score": 0.0,
        },
        {
            "pattern_id": "FP-008",
            "name": "SIEM connector self-test traffic",
            "description": "Elastic and Splunk connectors generate test events during health probes, triggering malware_detection rules on synthetic payloads.",
            "rule_family": "malware_detection",
            "match_criteria": {
                "source": "siem-connector",
                "entity_pattern": "connector-healthcheck-*",
                "time_window": "every 5 min",
            },
            "status": "revoked",
            "creator": "analyst.chen",
            "approver": "sr.analyst.martinez",
            "approval_date": (_now - timedelta(days=120)).isoformat(),
            "created_date": (_now - timedelta(days=122)).isoformat(),
            "expires_date": (_now - timedelta(days=30)).isoformat(),
            "auto_closed_count": 89,
            "precision_score": 72.5,
        },
        {
            "pattern_id": "FP-009",
            "name": "OT PLC firmware update chatter",
            "description": "Firmware update broadcasts from Zone1 PLCs flagged as network_scan during scheduled maintenance.",
            "rule_family": "network_scan",
            "match_criteria": {
                "source": "ot-ids",
                "entity_pattern": "plc-zone1-*",
                "time_window": "Saturday 22:00-Sunday 02:00 UTC",
            },
            "status": "active",
            "creator": "analyst.park",
            "approver": "sr.analyst.martinez",
            "approval_date": (_now - timedelta(days=85)).isoformat(),
            "created_date": (_now - timedelta(days=87)).isoformat(),
            "expires_date": (_now - timedelta(days=85) + timedelta(days=EXPIRY_DAYS)).isoformat(),
            "auto_closed_count": 33,
            "precision_score": 96.8,
        },
        {
            "pattern_id": "FP-010",
            "name": "DNS sinkhole redirect noise",
            "description": "Internal DNS sinkhole redirects trigger data_exfiltration alerts for blocked domains.",
            "rule_family": "data_exfiltration",
            "match_criteria": {
                "source": "dns-sinkhole",
                "entity_pattern": "sinkhole.internal.*",
                "time_window": "any",
            },
            "status": "active",
            "creator": "analyst.johansson",
            "approver": "sr.analyst.okonkwo",
            "approval_date": (_now - timedelta(days=10)).isoformat(),
            "created_date": (_now - timedelta(days=12)).isoformat(),
            "expires_date": (_now - timedelta(days=10) + timedelta(days=EXPIRY_DAYS)).isoformat(),
            "auto_closed_count": 67,
            "precision_score": 99.1,
        },
    ]

    # Compute days_until_expiry for each
    for p in patterns:
        if p["expires_date"]:
            try:
                exp = datetime.fromisoformat(p["expires_date"])
                delta = (exp - _now).days
                p["days_until_expiry"] = max(delta, 0)
            except (ValueError, TypeError):
                p["days_until_expiry"] = None
        else:
            p["days_until_expiry"] = None

    return patterns


def _compute_summary(patterns: list[dict[str, Any]]) -> dict[str, int]:
    total = len(patterns)
    active = sum(1 for p in patterns if p["status"] == "active")
    pending = sum(1 for p in patterns if p["status"] == "pending_approval")
    expiring_soon = sum(
        1 for p in patterns
        if p["status"] == "active"
        and p.get("days_until_expiry") is not None
        and p["days_until_expiry"] <= 14
    )
    return {
        "total": total,
        "active": active,
        "pending": pending,
        "expiring_soon": expiring_soon,
    }


# ---------------------------------------------------------------------------
# Page route
# ---------------------------------------------------------------------------

@router.get("/fp-patterns", response_class=HTMLResponse)
async def fp_patterns_page(request: Request) -> HTMLResponse:
    """Render FP pattern management page."""
    patterns: list[dict[str, Any]] = []

    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM fp_patterns ORDER BY created_date DESC",
            )
            patterns = [dict(r) for r in rows]
        except Exception:
            logger.info("FP patterns table not available, using demo data")

    if not patterns:
        patterns = _demo_patterns()

    summary = _compute_summary(patterns)

    # Collect unique rule families for filter dropdown
    rule_families = sorted({p["rule_family"] for p in patterns})

    return templates.TemplateResponse(
        request,
        "fp_patterns/index.html",
        {
            "patterns": patterns,
            "summary": summary,
            "rule_families": rule_families,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/api/fp-patterns/list")
async def api_fp_patterns_list(
    status: str = "",
    rule_family: str = "",
    search: str = "",
) -> list[dict[str, Any]]:
    """List FP patterns with optional filtering."""
    patterns: list[dict[str, Any]] = []

    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM fp_patterns ORDER BY created_date DESC",
            )
            patterns = [dict(r) for r in rows]
        except Exception:
            pass

    if not patterns:
        patterns = _demo_patterns()

    # Apply filters
    if status:
        patterns = [p for p in patterns if p["status"] == status]
    if rule_family:
        patterns = [p for p in patterns if p["rule_family"] == rule_family]
    if search:
        q = search.lower()
        patterns = [
            p for p in patterns
            if q in p["name"].lower() or q in p.get("description", "").lower()
        ]

    return patterns


@router.post("/api/investigations/{investigation_id}/mark-fp")
async def api_investigation_mark_fp(
    investigation_id: str, request: Request
) -> JSONResponse:
    """Mark a specific investigation as a false positive.

    FR-ATL-006: Blocked with HTTP 403 if the investigation is linked to a
    safety-relevant ATLAS detection.  The block is also emitted as a
    HIGH-severity audit event so the attempt is traceable.
    """
    body = await request.json()
    actor_id = body.get("actor_id", "unknown")

    db = get_db()

    # FR-ATL-006: Validate that this investigation is not safety-critical
    # before allowing FP classification.  ATLASSafetyGuard queries
    # atlas_detections and blocks if safety_relevant=TRUE.
    guard = ATLASSafetyGuard()
    result = await guard.validate_fp_candidate(investigation_id, db)
    if not result.allowed:
        await guard.audit_blocked_attempt(investigation_id, actor_id, None)
        raise HTTPException(
            status_code=403,
            detail=(
                result.reason
                or "FP classification blocked: investigation is linked to a "
                   "safety-relevant ATLAS detection and cannot be suppressed."
            ),
        )

    if db is None:
        return JSONResponse({
            "status": "marked_fp",
            "investigation_id": investigation_id,
            "demo": True,
        })

    try:
        await db.execute(
            """
            UPDATE investigation_state
            SET graph_state = jsonb_set(graph_state, '{classification}', '"false_positive"'),
                updated_at = NOW()
            WHERE investigation_id = $1
            """,
            investigation_id,
        )
    except Exception as exc:
        logger.error("Failed to mark investigation %s as FP: %s", investigation_id, exc)
        raise HTTPException(500, "Failed to update investigation state")

    return JSONResponse({
        "status": "marked_fp",
        "investigation_id": investigation_id,
    })


@router.post("/api/fp-patterns/approve")
async def api_fp_patterns_approve(request: Request) -> JSONResponse:
    """Two-person approve a pending FP pattern. Requires senior_analyst role."""
    body = await request.json()
    pattern_id = body.get("pattern_id", "")
    approver = body.get("approver", "")
    role = body.get("role", "")

    if not pattern_id or not approver:
        raise HTTPException(400, "pattern_id and approver are required")

    if role != "senior_analyst":
        raise HTTPException(403, "Only senior_analyst role can approve FP patterns")

    # In demo mode, return simulated approval
    db = get_db()
    if db is not None:
        try:
            row = await db.fetch_one(
                "SELECT * FROM fp_patterns WHERE pattern_id = $1", pattern_id,
            )
            if row:
                pattern = dict(row)
                if pattern.get("creator") == approver:
                    raise HTTPException(
                        409,
                        "Two-person rule: approver must differ from creator",
                    )
                now = datetime.now(timezone.utc)
                await db.execute(
                    """UPDATE fp_patterns
                       SET status = 'active', approver = $2,
                           approval_date = $3,
                           expires_date = $4
                       WHERE pattern_id = $1""",
                    pattern_id, approver, now.isoformat(),
                    (now + timedelta(days=EXPIRY_DAYS)).isoformat(),
                )
                return JSONResponse({"status": "approved", "pattern_id": pattern_id})
        except HTTPException:
            raise
        except Exception:
            logger.info("DB unavailable for approve, returning demo response")

    return JSONResponse({
        "status": "approved",
        "pattern_id": pattern_id,
        "approver": approver,
        "expires_date": (datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)).isoformat(),
        "demo": True,
    })


@router.post("/api/fp-patterns/reaffirm")
async def api_fp_patterns_reaffirm(request: Request) -> JSONResponse:
    """Reaffirm an FP pattern before 90-day expiry."""
    body = await request.json()
    pattern_id = body.get("pattern_id", "")
    reaffirmed_by = body.get("reaffirmed_by", "")

    if not pattern_id or not reaffirmed_by:
        raise HTTPException(400, "pattern_id and reaffirmed_by are required")

    db = get_db()
    if db is not None:
        try:
            now = datetime.now(timezone.utc)
            await db.execute(
                """UPDATE fp_patterns
                   SET expires_date = $2,
                       status = 'active'
                   WHERE pattern_id = $1""",
                pattern_id,
                (now + timedelta(days=EXPIRY_DAYS)).isoformat(),
            )
            return JSONResponse({
                "status": "reaffirmed",
                "pattern_id": pattern_id,
                "new_expires_date": (now + timedelta(days=EXPIRY_DAYS)).isoformat(),
            })
        except Exception:
            logger.info("DB unavailable for reaffirm, returning demo response")

    return JSONResponse({
        "status": "reaffirmed",
        "pattern_id": pattern_id,
        "new_expires_date": (
            datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)
        ).isoformat(),
        "demo": True,
    })


@router.post("/api/fp-patterns/revoke")
async def api_fp_patterns_revoke(request: Request) -> JSONResponse:
    """Revoke an FP pattern."""
    body = await request.json()
    pattern_id = body.get("pattern_id", "")
    revoked_by = body.get("revoked_by", "")

    if not pattern_id or not revoked_by:
        raise HTTPException(400, "pattern_id and revoked_by are required")

    db = get_db()
    if db is not None:
        try:
            await db.execute(
                """UPDATE fp_patterns
                   SET status = 'revoked',
                       revoked_by = $2,
                       revoked_at = $3
                   WHERE pattern_id = $1""",
                pattern_id, revoked_by,
                datetime.now(timezone.utc).isoformat(),
            )
            return JSONResponse({"status": "revoked", "pattern_id": pattern_id})
        except Exception:
            logger.info("DB unavailable for revoke, returning demo response")

    return JSONResponse({
        "status": "revoked",
        "pattern_id": pattern_id,
        "revoked_by": revoked_by,
        "demo": True,
    })
