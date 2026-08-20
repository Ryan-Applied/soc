"""Sentinel incident write-back and outbox tests."""

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel_adapter.writeback import (
    PermanentWritebackError,
    PostgresWritebackOutbox,
    SentinelIncidentClient,
    TransientWritebackError,
)


def _response(status: int, body: dict | None = None, text: str = ""):
    response = AsyncMock()
    response.status = status
    response.json = AsyncMock(return_value=body or {})
    response.text = AsyncMock(return_value=text)
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    return response


def _aiohttp(*responses):
    session = MagicMock()
    session.request = MagicMock(side_effect=responses)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    module = MagicMock()
    module.ClientSession = MagicMock(return_value=session)
    return module, session


def _payload():
    return {
        "subscription_id": "00000000-0000-0000-0000-000000000001",
        "resource_group": "soc-rg",
        "workspace_name": "sentinel-ws",
        "incident_name": "incident-guid",
        "comment": "ALUSKORT investigation summary",
        "tags": ["ALUSKORT-Investigated"],
    }


@pytest.mark.asyncio
async def test_writes_deterministic_comment_and_merges_incident_label():
    incident = {
        "etag": '"etag-1"',
        "properties": {
            "title": "Suspicious login",
            "severity": "High",
            "status": "Active",
            "labels": [{"labelName": "Existing", "labelType": "User"}],
        },
    }
    aiohttp, session = _aiohttp(
        _response(201, {"name": "comment"}),
        _response(200, incident),
        _response(200, incident),
    )
    credential = MagicMock()
    credential.get_token.return_value = SimpleNamespace(token="arm-token")
    client = SentinelIncidentClient(credential)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(sys.modules, "aiohttp", aiohttp)
        await client.write_investigation_summary(_payload(), "summary:inv-1")

    assert session.request.call_count == 3
    comment_call, get_call, update_call = session.request.call_args_list
    assert comment_call.args[0] == "PUT"
    assert "/comments/" in comment_call.args[1]
    assert get_call.args[0] == "GET"
    assert update_call.kwargs["headers"]["If-Match"] == '"etag-1"'
    labels = update_call.kwargs["json"]["properties"]["labels"]
    assert {label["labelName"] for label in labels} == {
        "Existing", "ALUSKORT-Investigated"
    }


@pytest.mark.asyncio
async def test_existing_label_skips_incident_update():
    incident = {
        "properties": {
            "labels": [{"labelName": "ALUSKORT-Investigated"}],
        },
    }
    aiohttp, session = _aiohttp(
        _response(200, {}),
        _response(200, incident),
    )
    credential = MagicMock()
    credential.get_token.return_value = SimpleNamespace(token="arm-token")
    client = SentinelIncidentClient(credential)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(sys.modules, "aiohttp", aiohttp)
        await client.write_investigation_summary(_payload(), "summary:inv-1")

    assert session.request.call_count == 2


@pytest.mark.asyncio
async def test_missing_resource_coordinates_is_permanent_failure():
    credential = MagicMock()
    client = SentinelIncidentClient(credential)
    with pytest.raises(PermanentWritebackError):
        await client.write_investigation_summary(
            {"incident_name": "incident-guid", "comment": "summary"},
            "summary:inv-1",
        )


@pytest.mark.asyncio
async def test_throttling_is_transient_failure():
    aiohttp, _ = _aiohttp(_response(429, text="throttled"))
    credential = MagicMock()
    credential.get_token.return_value = SimpleNamespace(token="arm-token")
    client = SentinelIncidentClient(credential)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(sys.modules, "aiohttp", aiohttp)
        with pytest.raises(TransientWritebackError):
            await client.write_investigation_summary(_payload(), "summary:inv-1")


@pytest.mark.asyncio
async def test_outbox_permanent_failure_moves_to_dead_letter():
    db = AsyncMock()
    outbox = PostgresWritebackOutbox(db)
    await outbox.fail("outbox-1", "bad payload", 1, permanent=True)
    args = db.execute.call_args.args
    assert args[2] == "dead_letter"


@pytest.mark.asyncio
async def test_outbox_completion_closes_investigation_atomically():
    db = AsyncMock()
    outbox = PostgresWritebackOutbox(db)
    await outbox.complete("outbox-1")
    query = db.execute.call_args.args[0]
    assert "status = 'completed'" in query
    assert "UPDATE investigation_state" in query
    assert "state = 'closed'" in query
