"""Tests for IOC Extractor agent — Story 7.2."""

import json

import pytest
from unittest.mock import AsyncMock, MagicMock

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.agents.ioc_extractor import IOCExtractorAgent, _parse_ioc_response


@pytest.fixture
def mock_gateway():
    gw = AsyncMock()
    gw.complete = AsyncMock(return_value=MagicMock(
        content=json.dumps({
            "iocs": [
                {"type": "ip", "value": "10.0.0.1"},
                {"type": "hash", "value": "abc123" * 10 + "abcd"},
                {"type": "domain", "value": "evil.example.com"},
            ]
        }),
        metrics=MagicMock(cost_usd=0.005),
    ))
    return gw


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get_ioc = AsyncMock(return_value=None)
    return redis


@pytest.fixture
def agent(mock_gateway, mock_redis):
    return IOCExtractorAgent(gateway=mock_gateway, redis_client=mock_redis)


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        alert_id="alert-001",
        tenant_id="tenant-A",
        entities={"ips": [{"primary_value": "10.0.0.1"}]},
    )


class TestIOCExtraction:
    @pytest.mark.asyncio
    async def test_extracts_iocs(self, agent, state):
        result = await agent.execute(state)
        assert len(result.ioc_matches) == 3
        assert result.ioc_matches[0]["type"] == "ip"
        assert result.ioc_matches[0]["value"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_transitions_to_parsing(self, agent, state):
        result = await agent.execute(state)
        assert result.state == InvestigationState.PARSING

    @pytest.mark.asyncio
    async def test_increments_llm_calls(self, agent, state):
        result = await agent.execute(state)
        assert result.llm_calls == 1

    @pytest.mark.asyncio
    async def test_tracks_cost(self, agent, state):
        result = await agent.execute(state)
        assert result.total_cost_usd == pytest.approx(0.005)

    @pytest.mark.asyncio
    async def test_calls_gateway(self, agent, state, mock_gateway):
        await agent.execute(state)
        mock_gateway.complete.assert_called_once()

    @pytest.mark.asyncio
    async def test_queries_redis_per_ioc(self, agent, state, mock_redis):
        await agent.execute(state)
        assert mock_redis.get_ioc.call_count == 3
        mock_redis.get_ioc.assert_any_await("tenant-A", "ip", "10.0.0.1")

    @pytest.mark.asyncio
    async def test_enriches_from_redis(self, agent, state, mock_redis):
        mock_redis.get_ioc.return_value = {
            "confidence": 0.95,
            "severity": "high",
            "campaigns": ["APT28"],
        }
        result = await agent.execute(state)
        assert result.ioc_matches[0].get("confidence") == 0.95
        assert result.ioc_matches[0].get("campaigns") == ["APT28"]

    @pytest.mark.asyncio
    async def test_tracks_query_count(self, agent, state):
        result = await agent.execute(state)
        assert result.queries_executed == 3


class TestParseIOCResponse:
    def test_parse_dict_with_iocs(self):
        content = json.dumps({"iocs": [{"type": "ip", "value": "1.2.3.4"}]})
        result = _parse_ioc_response(content)
        assert len(result) == 1
        assert result[0]["type"] == "ip"

    def test_parse_list(self):
        content = json.dumps([{"type": "hash", "value": "abc"}])
        result = _parse_ioc_response(content)
        assert len(result) == 1

    def test_parse_invalid_json(self):
        result = _parse_ioc_response("not json")
        assert result == []

    def test_parse_empty_string(self):
        result = _parse_ioc_response("")
        assert result == []

    def test_parse_no_iocs_key(self):
        content = json.dumps({"data": [1, 2, 3]})
        result = _parse_ioc_response(content)
        assert result == []
