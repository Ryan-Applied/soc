"""Tests for investigation persistence — Story 7.1."""

import json

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.persistence import InvestigationRepository, _make_decision_entry


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.execute = AsyncMock()
    db.fetch_one = AsyncMock(return_value=None)
    db.fetch_many = AsyncMock(return_value=[])
    return db


@pytest.fixture
def repo(mock_db):
    return InvestigationRepository(mock_db)


@pytest.fixture
def sample_state():
    return GraphState(
        investigation_id="inv-test-001",
        alert_id="alert-001",
        tenant_id="tenant-A",
        severity="high",
    )


class TestMakeDecisionEntry:
    def test_basic_entry(self):
        entry = _make_decision_entry("test_agent", "test_action")
        assert entry["agent"] == "test_agent"
        assert entry["action"] == "test_action"
        assert "timestamp" in entry
        assert "confidence" not in entry

    def test_entry_with_confidence(self):
        entry = _make_decision_entry("agent", "action", confidence=0.85)
        assert entry["confidence"] == 0.85

    def test_entry_with_details(self):
        entry = _make_decision_entry(
            "agent", "action", details={"key": "value"}
        )
        assert entry["details"]["key"] == "value"


class TestSave:
    @pytest.mark.asyncio
    async def test_save_calls_execute(self, repo, mock_db, sample_state):
        await repo.save(sample_state)
        mock_db.execute.assert_called_once()
        args = mock_db.execute.call_args[0]
        assert "INSERT INTO investigation_state" in args[0]
        assert args[1] == "inv-test-001"
        assert args[2] == "alert-001"
        assert args[3] == "tenant-A"
        assert args[4] == "received"

    @pytest.mark.asyncio
    async def test_save_includes_graph_state(self, repo, mock_db, sample_state):
        await repo.save(sample_state)
        args = mock_db.execute.call_args[0]
        state_json = args[5]
        data = json.loads(state_json)
        assert data["investigation_id"] == "inv-test-001"


class TestLoad:
    @pytest.mark.asyncio
    async def test_load_returns_none_when_missing(self, repo, mock_db):
        result = await repo.load("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_load_returns_graphstate(self, repo, mock_db, sample_state):
        mock_db.fetch_one.return_value = {
            "graph_state": sample_state.model_dump()
        }
        result = await repo.load("inv-test-001")
        assert result is not None
        assert result.investigation_id == "inv-test-001"
        assert result.alert_id == "alert-001"

    @pytest.mark.asyncio
    async def test_load_handles_json_string(self, repo, mock_db, sample_state):
        mock_db.fetch_one.return_value = {
            "graph_state": sample_state.model_dump_json()
        }
        result = await repo.load("inv-test-001")
        assert result is not None
        assert result.investigation_id == "inv-test-001"


class TestTransition:
    @pytest.mark.asyncio
    async def test_transition_updates_state(self, repo, sample_state):
        result = await repo.transition(
            sample_state,
            InvestigationState.PARSING,
            agent="ioc_extractor",
            action="start_extraction",
        )
        assert result.state == InvestigationState.PARSING

    @pytest.mark.asyncio
    async def test_transition_appends_decision(self, repo, sample_state):
        result = await repo.transition(
            sample_state,
            InvestigationState.PARSING,
            agent="ioc_extractor",
            action="start_extraction",
            confidence=0.9,
        )
        assert len(result.decision_chain) == 1
        assert result.decision_chain[0]["agent"] == "ioc_extractor"
        assert result.decision_chain[0]["confidence"] == 0.9

    @pytest.mark.asyncio
    async def test_transition_persists(self, repo, mock_db, sample_state):
        await repo.transition(
            sample_state,
            InvestigationState.ENRICHING,
            agent="graph",
            action="start_enrichment",
        )
        mock_db.execute.assert_called_once()


class TestListByState:
    @pytest.mark.asyncio
    async def test_list_empty(self, repo, mock_db):
        result = await repo.list_by_state(InvestigationState.AWAITING_HUMAN)
        assert result == []

    @pytest.mark.asyncio
    async def test_list_queries_correct_state(self, repo, mock_db):
        await repo.list_by_state(InvestigationState.AWAITING_HUMAN, limit=10)
        args = mock_db.fetch_many.call_args[0]
        assert "awaiting_human" in args
