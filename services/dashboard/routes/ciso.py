"""CISO Executive Dashboard — graphed metrics for C-suite reporting.

KPIs: MTTD, MTTR, automation rate, FP accuracy, cost efficiency,
risk posture, SLA compliance, and threat landscape trends.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


# -- Demo metrics for when DB is unavailable ---------------------------------

def _demo_ciso_metrics() -> dict[str, Any]:
    """Rich demo data set for the CISO dashboard."""
    now = datetime.now(timezone.utc)

    # 30-day daily trend data
    daily_labels = [(now - timedelta(days=29 - i)).strftime("%b %d") for i in range(30)]

    return {
        # --- KPI Cards ---
        "mttd_seconds": 22,
        "mttd_display": "22s",
        "mttd_target": 30,
        "mttr_minutes": 8.4,
        "mttr_display": "8.4m",
        "mttr_target": 15,
        "automation_rate": 84.2,
        "automation_target": 80,
        "fp_accuracy": 98.6,
        "fp_target": 98,
        "total_investigations_30d": 4827,
        "total_auto_closed": 2941,
        "total_escalated": 312,
        "total_cost_30d": 387.42,
        "cost_target": 400,
        "cost_per_investigation": 0.08,
        "sla_compliance": 96.8,
        "sla_target": 95,
        "risk_posture_score": 78,

        # --- Chart: Daily alert volume (30 days) ---
        "daily_labels": daily_labels,
        "daily_alerts": [
            142, 156, 138, 201, 178, 165, 149, 187, 195, 211,
            168, 144, 159, 223, 198, 176, 162, 189, 205, 234,
            192, 171, 153, 218, 201, 185, 174, 196, 208, 221,
        ],
        "daily_auto_closed": [
            118, 131, 115, 172, 149, 138, 125, 158, 165, 179,
            141, 120, 134, 190, 167, 148, 136, 160, 174, 199,
            162, 144, 128, 185, 170, 156, 147, 166, 176, 187,
        ],
        "daily_escalated": [
            8, 11, 9, 14, 12, 10, 9, 13, 11, 15,
            10, 8, 10, 16, 14, 11, 9, 12, 13, 17,
            12, 10, 8, 15, 13, 11, 10, 12, 14, 16,
        ],

        # --- Chart: MTTD/MTTR trend (30 days) ---
        "daily_mttd": [
            28, 26, 25, 31, 27, 24, 23, 29, 26, 32,
            25, 22, 24, 30, 27, 23, 22, 26, 24, 28,
            23, 21, 22, 27, 24, 22, 21, 23, 22, 22,
        ],
        "daily_mttr": [
            12.1, 11.4, 10.8, 13.2, 11.9, 10.5, 10.1, 12.3, 11.0, 13.8,
            10.7, 9.8, 10.2, 12.9, 11.5, 10.0, 9.6, 11.1, 10.3, 12.0,
            9.9, 9.2, 9.0, 11.4, 10.1, 9.5, 9.1, 9.8, 8.9, 8.4,
        ],

        # --- Chart: Severity distribution (current open) ---
        "severity_open": {"critical": 3, "high": 12, "medium": 28, "low": 41, "informational": 8},

        # --- Chart: Cost trend (30 days) ---
        "daily_cost": [
            11.20, 12.80, 10.50, 16.40, 14.30, 12.10, 10.90, 15.20, 14.60, 17.80,
            12.40, 10.20, 11.80, 18.10, 15.40, 13.00, 11.60, 14.50, 15.80, 19.20,
            14.00, 12.30, 11.10, 17.50, 15.20, 13.40, 12.50, 14.80, 15.60, 16.90,
        ],

        # --- Chart: Top MITRE tactics (30 days) ---
        "top_tactics": [
            {"tactic": "Initial Access", "count": 892},
            {"tactic": "Execution", "count": 641},
            {"tactic": "Persistence", "count": 523},
            {"tactic": "Privilege Escalation", "count": 418},
            {"tactic": "Defense Evasion", "count": 387},
            {"tactic": "Lateral Movement", "count": 312},
            {"tactic": "Collection", "count": 245},
            {"tactic": "Exfiltration", "count": 189},
        ],

        # --- Chart: Automation rate trend (30 days) ---
        "daily_automation": [
            79.2, 80.1, 81.4, 82.0, 81.5, 82.8, 83.1, 82.6, 83.5, 83.0,
            83.8, 84.2, 83.9, 84.5, 84.1, 84.8, 84.3, 85.0, 84.6, 85.2,
            84.8, 85.1, 84.5, 85.3, 84.9, 85.4, 85.0, 85.2, 84.8, 84.2,
        ],

        # --- SLA compliance by severity ---
        "sla_by_severity": {
            "critical": {"total": 48, "met": 45, "pct": 93.8},
            "high": {"total": 312, "met": 298, "pct": 95.5},
            "medium": {"total": 1204, "met": 1178, "pct": 97.8},
            "low": {"total": 3263, "met": 3231, "pct": 99.0},
        },

        # --- CTEM exposure summary ---
        "ctem_summary": {
            "total": 247,
            "critical": 8,
            "high": 34,
            "medium": 89,
            "low": 116,
            "remediated_30d": 62,
            "overdue": 5,
        },

        # --- Adversarial AI summary ---
        "adversarial_summary": {
            "injection_attempts_30d": 47,
            "blocked": 47,
            "atlas_detections_30d": 12,
            "models_monitored": 6,
        },

        # --- Investigation outcomes (30d) ---
        "outcomes": {
            "true_positive": 1574,
            "false_positive": 2941,
            "escalated": 312,
        },
    }


def _empty_ciso_metrics() -> dict[str, Any]:
    """Return a complete, truthful zero-value dashboard payload."""
    now = datetime.now(timezone.utc)
    daily_labels = [(now - timedelta(days=29 - i)).strftime("%b %d") for i in range(30)]
    zero_days = [0] * 30

    return {
        "mttd_seconds": 0,
        "mttd_display": "-",
        "mttd_target": 30,
        "mttr_minutes": 0.0,
        "mttr_display": "-",
        "mttr_target": 15,
        "automation_rate": 0.0,
        "automation_target": 80,
        "fp_accuracy": 0.0,
        "fp_target": 98,
        "total_investigations_30d": 0,
        "total_auto_closed": 0,
        "total_escalated": 0,
        "total_cost_30d": 0.0,
        "cost_target": 400,
        "cost_per_investigation": 0.0,
        "sla_compliance": 0.0,
        "sla_target": 95,
        "risk_posture_score": 0,
        "daily_labels": daily_labels,
        "daily_alerts": zero_days.copy(),
        "daily_auto_closed": zero_days.copy(),
        "daily_escalated": zero_days.copy(),
        "daily_mttd": zero_days.copy(),
        "daily_mttr": zero_days.copy(),
        "daily_cost": zero_days.copy(),
        "daily_automation": zero_days.copy(),
        "severity_open": {},
        "top_tactics": [],
        "sla_by_severity": {},
        "ctem_summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "remediated_30d": 0,
            "overdue": 0,
        },
        "adversarial_summary": {
            "injection_attempts_30d": 0,
            "blocked": 0,
            "atlas_detections_30d": 0,
            "models_monitored": 0,
        },
        "outcomes": {
            "true_positive": 0,
            "false_positive": 0,
            "escalated": 0,
        },
    }


async def _fetch_ciso_metrics() -> dict[str, Any]:
    """Fetch live metrics without substituting synthetic production values."""
    db = get_db()
    if db is None:
        return _empty_ciso_metrics()

    now = datetime.now(timezone.utc)
    metrics = _empty_ciso_metrics()

    try:
        # ----------------------------------------------------------------
        # Core investigation counts (30d)
        # ----------------------------------------------------------------
        row = await db.fetch_one(
            "SELECT COUNT(*) AS cnt FROM investigation_state "
            "WHERE created_at >= NOW() - INTERVAL '30 days'"
        )
        total_30d = row["cnt"] if row else 0
        metrics["total_investigations_30d"] = total_30d

        row = await db.fetch_one(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE inv.state = 'closed' AND decision.investigation_id IS NULL
                ) AS auto_closed,
                COUNT(*) FILTER (
                    WHERE inv.state = 'awaiting_human'
                       OR decision.investigation_id IS NOT NULL
                ) AS escalated
            FROM investigation_state AS inv
            LEFT JOIN approval_decisions AS decision
              ON decision.investigation_id = inv.investigation_id
            WHERE inv.created_at >= NOW() - INTERVAL '30 days'
            """
        )
        if row:
            metrics["total_auto_closed"] = row["auto_closed"] or 0
            metrics["total_escalated"] = row["escalated"] or 0

        # ----------------------------------------------------------------
        # Severity distribution (currently open)
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            "SELECT graph_state->>'severity' AS sev, COUNT(*) AS cnt "
            "FROM investigation_state WHERE state NOT IN ('closed','failed') "
            "AND created_at >= NOW() - INTERVAL '30 days' "
            "GROUP BY graph_state->>'severity'"
        )
        metrics["severity_open"] = {r["sev"]: r["cnt"] for r in rows if r["sev"]}

        # ----------------------------------------------------------------
        # MTTR (closed investigations, last 7 days)
        # ----------------------------------------------------------------
        row = await db.fetch_one(
            "SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) AS avg_sec "
            "FROM investigation_state WHERE state = 'closed' "
            "AND updated_at >= NOW() - INTERVAL '7 days'"
        )
        if row and row["avg_sec"] is not None:
            mttr_min = round(float(row["avg_sec"]) / 60, 1)
            metrics["mttr_minutes"] = mttr_min
            metrics["mttr_display"] = f"{mttr_min}m"

        # ----------------------------------------------------------------
        # LLM cost (30d)
        # ----------------------------------------------------------------
        row = await db.fetch_one(
            "SELECT COALESCE(SUM(total_cost_usd), 0) AS cost "
            "FROM investigation_state WHERE created_at >= NOW() - INTERVAL '30 days'"
        )
        cost_30d = round(float(row["cost"] or 0), 2) if row else 0.0
        metrics["total_cost_30d"] = cost_30d
        if total_30d > 0:
            metrics["cost_per_investigation"] = round(cost_30d / total_30d, 4)

        # ----------------------------------------------------------------
        # Daily alert volume chart (30 days) — real data
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            """
            SELECT
                DATE(inv.created_at AT TIME ZONE 'UTC') AS day,
                COUNT(*) AS total,
                COUNT(*) FILTER (
                    WHERE inv.state = 'closed' AND decision.investigation_id IS NULL
                ) AS auto_closed,
                COUNT(*) FILTER (
                    WHERE inv.state = 'awaiting_human'
                       OR decision.investigation_id IS NOT NULL
                ) AS escalated,
                COALESCE(SUM(inv.total_cost_usd), 0) AS cost
            FROM investigation_state AS inv
            LEFT JOIN approval_decisions AS decision
              ON decision.investigation_id = inv.investigation_id
            WHERE inv.created_at >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(inv.created_at AT TIME ZONE 'UTC')
            ORDER BY day
            """
        )
        if rows:
            day_map: dict[str, dict] = {
                str(r["day"]): {
                    "total": r["total"],
                    "auto_closed": r["auto_closed"],
                    "escalated": r["escalated"],
                    "cost": float(r["cost"]),
                }
                for r in rows
            }
            # Build full 30-day arrays, filling missing days with 0
            labels, alerts, auto_closed_list, escalated_list, cost_list = [], [], [], [], []
            for i in range(30):
                day = (now - timedelta(days=29 - i)).date()
                key = str(day)
                label = day.strftime("%b %d")
                d = day_map.get(key, {})
                labels.append(label)
                alerts.append(d.get("total", 0))
                auto_closed_list.append(d.get("auto_closed", 0))
                escalated_list.append(d.get("escalated", 0))
                cost_list.append(round(d.get("cost", 0.0), 2))

            metrics["daily_labels"] = labels
            metrics["daily_alerts"] = alerts
            metrics["daily_auto_closed"] = auto_closed_list
            metrics["daily_escalated"] = escalated_list
            metrics["daily_cost"] = cost_list

        # ----------------------------------------------------------------
        # Automation rate (30d)
        # ----------------------------------------------------------------
        if total_30d > 0:
            metrics["automation_rate"] = round(
                metrics["total_auto_closed"] / total_30d * 100, 1
            )

        # ----------------------------------------------------------------
        # Investigation outcomes (30d classification breakdown)
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            """
            SELECT graph_state->>'classification' AS cls, COUNT(*) AS cnt
            FROM investigation_state
            WHERE state = 'closed'
            AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY graph_state->>'classification'
            """
        )
        if rows:
            outcome_map = {r["cls"]: r["cnt"] for r in rows if r["cls"]}
            tp = outcome_map.get("true_positive", 0)
            fp = outcome_map.get("false_positive", 0) + outcome_map.get("benign_true_positive", 0)
            metrics["outcomes"] = {
                "true_positive": tp,
                "false_positive": fp,
                "escalated": metrics["total_escalated"],
            }

        row = await db.fetch_one(
            """
            SELECT AVG(CASE WHEN feedback.classification_correct THEN 1.0 ELSE 0.0 END)
                       * 100 AS accuracy
            FROM analyst_feedback AS feedback
            JOIN investigation_state AS inv
              ON inv.investigation_id = feedback.investigation_id
            WHERE feedback.submitted_at >= NOW() - INTERVAL '30 days'
              AND inv.graph_state->>'classification'
                  IN ('false_positive', 'benign_true_positive')
            """
        )
        if row and row["accuracy"] is not None:
            metrics["fp_accuracy"] = round(float(row["accuracy"]), 1)

        # ----------------------------------------------------------------
        # Top MITRE tactics (30d) — extracted from graph_state JSON
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            """
            SELECT tactic, COUNT(*) AS cnt
            FROM investigation_state,
                 jsonb_array_elements_text(
                     CASE
                         WHEN jsonb_typeof(graph_state->'case_facts'->'tactics') = 'array'
                         THEN graph_state->'case_facts'->'tactics'
                         ELSE '[]'::jsonb
                     END
                 ) AS tactic
            WHERE created_at >= NOW() - INTERVAL '30 days'
            GROUP BY tactic
            ORDER BY cnt DESC
            LIMIT 8
            """
        )
        if rows:
            tactics = [{"tactic": r["tactic"], "count": r["cnt"]} for r in rows]
            if tactics:
                metrics["top_tactics"] = tactics

        # ----------------------------------------------------------------
        # CTEM summary from ctem_exposures
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            """
            SELECT
                severity,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'Open') AS open_cnt,
                COUNT(*) FILTER (WHERE status = 'Remediated'
                    AND updated_at >= NOW() - INTERVAL '30 days') AS remediated_30d,
                COUNT(*) FILTER (WHERE sla_deadline < NOW() AND status = 'Open') AS overdue
            FROM ctem_exposures
            GROUP BY severity
            """
        )
        if rows:
            ctem: dict[str, Any] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                                     "remediated_30d": 0, "overdue": 0}
            for r in rows:
                sev = (r["severity"] or "").lower()
                cnt = r["open_cnt"] or 0
                ctem["total"] += cnt
                if sev in ctem:
                    ctem[sev] = cnt
                ctem["remediated_30d"] += r["remediated_30d"] or 0
                ctem["overdue"] += r["overdue"] or 0
            metrics["ctem_summary"] = ctem

        # ----------------------------------------------------------------
        # SLA compliance by severity (ctem_exposures)
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            """
            SELECT
                severity,
                COUNT(*) AS total,
                COUNT(*) FILTER (
                    WHERE (status = 'Remediated' AND updated_at <= sla_deadline)
                       OR (status = 'Open' AND sla_deadline >= NOW())
                ) AS met
            FROM ctem_exposures
            WHERE created_at >= NOW() - INTERVAL '30 days'
            GROUP BY severity
            """
        )
        if rows:
            sla: dict[str, Any] = {}
            for r in rows:
                sev = (r["severity"] or "").lower()
                total = r["total"] or 0
                met = r["met"] or 0
                pct = round(met / total * 100, 1) if total > 0 else 100.0
                sla[sev] = {"total": total, "met": met, "pct": pct}
            metrics["sla_by_severity"] = sla
            all_total = sum(v["total"] for v in sla.values())
            all_met = sum(v["met"] for v in sla.values())
            if all_total > 0:
                metrics["sla_compliance"] = round(all_met / all_total * 100, 1)

        # ----------------------------------------------------------------
        # Daily MTTD & automation rate trends (30 days)
        # ----------------------------------------------------------------
        rows = await db.fetch_many(
            """
            SELECT
                DATE(inv.created_at AT TIME ZONE 'UTC') AS day,
                AVG(
                    EXTRACT(EPOCH FROM (
                        inv.created_at
                        - COALESCE(
                            (inv.graph_state->'case_facts'->>'timestamp')::timestamptz,
                            inv.created_at
                          )
                    ))
                ) AS avg_mttd_sec,
                ROUND(
                    COUNT(*) FILTER (
                        WHERE inv.state = 'closed'
                          AND decision.investigation_id IS NULL
                    )::numeric
                    / NULLIF(COUNT(*), 0) * 100, 1
                ) AS automation_pct
            FROM investigation_state AS inv
            LEFT JOIN approval_decisions AS decision
              ON decision.investigation_id = inv.investigation_id
            WHERE inv.created_at >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(inv.created_at AT TIME ZONE 'UTC')
            ORDER BY day
            """
        )
        if rows:
            mttd_day_map = {
                str(r["day"]): {
                    "mttd": max(0.0, float(r["avg_mttd_sec"] or 0)),
                    "automation": float(r["automation_pct"] or 0),
                }
                for r in rows
            }
            mttd_list, auto_list = [], []
            for i in range(30):
                day = (now - timedelta(days=29 - i)).date()
                d = mttd_day_map.get(str(day), {})
                mttd_list.append(round(d.get("mttd", 0), 1))
                auto_list.append(d.get("automation", 0))

            metrics["daily_mttd"] = mttd_list
            metrics["daily_automation"] = auto_list
            recent_mttd = [value for value in mttd_list[-7:] if value > 0]
            if recent_mttd:
                avg_mttd = round(sum(recent_mttd) / len(recent_mttd), 1)
                metrics["mttd_seconds"] = int(avg_mttd)
                metrics["mttd_display"] = f"{int(avg_mttd)}s"

        # ----------------------------------------------------------------
        # Risk posture score — derived from open critical/high CTEM + open investigations
        # ----------------------------------------------------------------
        try:
            row = await db.fetch_one(
                """
                SELECT
                    COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'Open') AS crit,
                    COUNT(*) FILTER (WHERE severity = 'high'     AND status = 'Open') AS high,
                    COUNT(*) FILTER (WHERE severity = 'medium'   AND status = 'Open') AS med
                FROM ctem_exposures
                """
            )
            if row:
                crit = row["crit"] or 0
                high = row["high"] or 0
                med = row["med"] or 0
                penalty = min(100, crit * 8 + high * 2 + med // 5)
                score = max(0, 100 - penalty)
                metrics["risk_posture_score"] = score
        except Exception as exc:
            logger.warning("CISO risk posture query failed: %s", exc)

        # ----------------------------------------------------------------
        # Adversarial AI — atlas_detections table
        # ----------------------------------------------------------------
        try:
            row = await db.fetch_one(
                "SELECT COUNT(*) AS cnt FROM atlas_detections "
                "WHERE fired_at >= NOW() - INTERVAL '30 days'"
            )
            if row and row["cnt"] is not None:
                metrics["adversarial_summary"]["atlas_detections_30d"] = row["cnt"]
        except Exception as exc:
            logger.warning("CISO ATLAS query failed: %s", exc)

    except Exception as exc:
        logger.warning("CISO metrics query failed; returning available live values: %s", exc)

    return metrics


@router.get("/ciso", response_class=HTMLResponse)
async def ciso_dashboard(request: Request) -> HTMLResponse:
    """Render the CISO executive dashboard."""
    metrics = await _fetch_ciso_metrics()
    return templates.TemplateResponse(
        request,
        "ciso/index.html",
        {"m": metrics},
    )


@router.get("/api/ciso/metrics")
async def api_ciso_metrics() -> dict[str, Any]:
    """JSON endpoint for CISO metrics (supports auto-refresh)."""
    return await _fetch_ciso_metrics()
