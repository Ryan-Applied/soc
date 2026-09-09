"""Readiness must reflect Sentinel connectivity, not only a running task."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from sentinel_adapter import service


class RunningTask:
    def done(self) -> bool:
        return False


@pytest.fixture(autouse=True)
def restore_runtime():
    previous = (
        service.runtime.connector,
        service.runtime.task,
        service.runtime.db,
    )
    yield
    service.runtime.connector, service.runtime.task, service.runtime.db = previous


def set_runtime(*, last_success_at=None, last_error=None) -> None:
    service.runtime.connector = SimpleNamespace(
        _running=True,
        last_success_at=last_success_at,
        last_error=last_error,
    )
    service.runtime.task = RunningTask()
    service.runtime.db = AsyncMock()
    service.runtime.db.health_check.return_value = True


@pytest.mark.asyncio
async def test_not_ready_before_initial_sentinel_query():
    set_runtime()

    with pytest.raises(HTTPException, match="initial query") as exc_info:
        await service.ready()

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_not_ready_while_sentinel_polling_is_failing():
    set_runtime(last_error="credential unavailable")

    with pytest.raises(HTTPException, match="credential unavailable") as exc_info:
        await service.ready()

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_ready_after_successful_sentinel_query():
    set_runtime(last_success_at="2026-09-09T08:00:00+00:00")

    result = await service.ready()

    assert result["status"] == "ready"
