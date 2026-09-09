"""Tests for safe test-harness persistence behaviour."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from services.dashboard import app as dashboard_app  # noqa: F401
from services.dashboard.routes import test_harness


def test_related_table_writes_are_opt_in():
    request = test_harness.FireRequest()

    assert request.write_ctem is False
    assert request.write_iocs is False
    assert request.write_cti is False


@pytest.mark.asyncio
async def test_ctem_writer_returns_database_errors():
    db = AsyncMock()
    db.execute.side_effect = RuntimeError("ctem unavailable")
    scenario = {
        "tag": "apt",
        "techniques": ["T1059"],
        "ctem_exposures": [{
            "title": "Synthetic exposure",
            "asset": "host-1",
            "severity": "high",
        }],
    }

    errors = await test_harness._write_ctem_to_db(
        db,
        scenario,
        "tenant-1",
        datetime.now(timezone.utc),
    )

    assert len(errors) == 1
    assert "ctem unavailable" in errors[0]


@pytest.mark.asyncio
async def test_clear_reports_partial_failure():
    db = AsyncMock()
    db.execute.side_effect = [
        "DELETE 2",
        RuntimeError("CTEM delete failed"),
        "DELETE 1",
        "DELETE 1",
    ]

    with patch.object(test_harness, "get_db", return_value=db):
        result = await test_harness.clear_test_data()

    assert result["status"] == "partial"
    assert result["tables"]["ctem_exposures"].startswith("error:")
