"""Regression tests for truthful CISO dashboard metrics."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from services.dashboard import app as dashboard_app  # noqa: F401
from services.dashboard.routes import ciso


class CisoDatabase:
    def __init__(self) -> None:
        self.queries: list[str] = []

    async def fetch_one(self, query: str, *args):
        self.queries.append(query)
        if "COUNT(*) AS cnt FROM investigation_state" in query:
            return {"cnt": 4}
        if "AS auto_closed" in query:
            return {"auto_closed": 2, "escalated": 1}
        if "AS avg_sec" in query:
            return {"avg_sec": 120.0}
        if "SUM(total_cost_usd)" in query:
            return {"cost": 2.0}
        if "AS accuracy" in query:
            return {"accuracy": 75.0}
        if "AS crit" in query:
            return {"crit": 1, "high": 2, "med": 5}
        if "FROM atlas_detections" in query:
            return {"cnt": 3}
        raise AssertionError(f"Unexpected fetch_one query: {query}")

    async def fetch_many(self, query: str, *args):
        self.queries.append(query)
        if "GROUP BY graph_state->>'severity'" in query:
            return [{"sev": "high", "cnt": 2}]
        if "avg_mttd_sec" in query:
            return [{
                "day": datetime.now(timezone.utc).date(),
                "avg_mttd_sec": 12.0,
                "automation_pct": 50.0,
            }]
        if "DATE(inv.created_at" in query:
            return [{
                "day": datetime.now(timezone.utc).date(),
                "total": 4,
                "auto_closed": 2,
                "escalated": 1,
                "cost": 2.0,
            }]
        if "AS cls" in query:
            return [
                {"cls": "true_positive", "cnt": 1},
                {"cls": "false_positive", "cnt": 2},
            ]
        if "jsonb_array_elements_text" in query:
            return [{"tactic": "Execution", "cnt": 2}]
        if "FROM ctem_exposures" in query and "open_cnt" in query:
            return [{
                "severity": "high",
                "total": 2,
                "open_cnt": 1,
                "remediated_30d": 1,
                "overdue": 0,
            }]
        if "AS met" in query:
            return [{"severity": "high", "total": 2, "met": 2}]
        raise AssertionError(f"Unexpected fetch_many query: {query}")


@pytest.mark.asyncio
async def test_ciso_metrics_use_live_values_and_correct_schema_columns():
    db = CisoDatabase()

    with patch.object(ciso, "get_db", return_value=db):
        metrics = await ciso._fetch_ciso_metrics()

    assert metrics["total_investigations_30d"] == 4
    assert metrics["total_auto_closed"] == 2
    assert metrics["total_escalated"] == 1
    assert metrics["automation_rate"] == 50.0
    assert metrics["fp_accuracy"] == 75.0
    assert metrics["adversarial_summary"]["atlas_detections_30d"] == 3
    sql = "\n".join(db.queries)
    assert "fired_at" in sql
    assert "detected_at" not in sql
    assert "decision.investigation_id IS NULL" in sql


@pytest.mark.asyncio
async def test_ciso_metrics_do_not_show_demo_values_without_a_database():
    with patch.object(ciso, "get_db", return_value=None):
        metrics = await ciso._fetch_ciso_metrics()

    assert metrics["total_investigations_30d"] == 0
    assert metrics["total_auto_closed"] == 0
    assert metrics["mttd_display"] == "-"
    assert metrics["daily_alerts"] == [0] * 30
