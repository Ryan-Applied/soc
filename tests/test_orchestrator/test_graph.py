"""Tests for Investigation Graph — Story 7.8."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.graph import InvestigationGraph
from orchestrator.persistence import InvestigationRepository
from orchestrator.fp_shortcircuit import FPMatchResult


def _make_agent(state_override: dict | None = None):
    """Create a mock agent that returns modified state."""
    agent = AsyncMock()

    async def execute(state):
        if state_override:
            for k, v in state_override.items():
                setattr(state, k, v)
        return state

    agent.execute = execute
    return agent


@pytest.fixture
def mock_repo():
    repo = AsyncMock(spec=InvestigationRepository)
    repo.save = AsyncMock()

    async def transition(state, new_state, agent, action, **kwargs):
        state.state = new_state
        state.decision_chain.append({"agent": agent, "action": action})
        return state

    repo.transition = transition
    repo.load = AsyncMock(return_value=None)
    return repo


@pytest.fixture
def mock_ioc():
    return _make_agent({"state": InvestigationState.PARSING})


@pytest.fixture
def mock_enricher():
    return _make_agent({
        "state": InvestigationState.ENRICHING,
        "risk_state": "medium",
        "ueba_context": [{"risk_state": "medium"}],
    })


@pytest.fixture
def mock_ctem():
    return _make_agent({
        "ctem_exposures": [{"exposure_key": "exp-001"}],
    })


@pytest.fixture
def mock_atlas():
    return _make_agent({
        "atlas_techniques": [{"atlas_id": "AML.T0020"}],
    })


@pytest.fixture
def mock_reasoning():
    return _make_agent({
        "state": InvestigationState.RESPONDING,
        "classification": "true_positive",
        "confidence": 0.85,
    })


@pytest.fixture
def mock_response():
    return _make_agent({
        "state": InvestigationState.CLOSED,
    })


@pytest.fixture
def mock_fp():
    fp = AsyncMock()
    fp.check = AsyncMock(return_value=FPMatchResult(matched=False))
    fp.apply_shortcircuit = MagicMock()
    return fp


@pytest.fixture
def graph(
    mock_repo, mock_ioc, mock_enricher, mock_ctem,
    mock_atlas, mock_reasoning, mock_response, mock_fp,
):
    return InvestigationGraph(
        repository=mock_repo,
        ioc_extractor=mock_ioc,
        context_enricher=mock_enricher,
        ctem_correlator=mock_ctem,
        atlas_mapper=mock_atlas,
        reasoning_agent=mock_reasoning,
        response_agent=mock_response,
        fp_shortcircuit=mock_fp,
    )


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_full_pipeline(self, graph):
        result = await graph.run(
            alert_id="alert-001",
            tenant_id="tenant-A",
            entities={"ips": [{"primary_value": "10.0.0.1"}]},
            alert_title="Test Alert",
            severity="high",
        )
        assert result.state == InvestigationState.CLOSED
        assert result.classification == "true_positive"
        assert result.confidence == 0.85

    @pytest.mark.asyncio
    async def test_generates_investigation_id(self, graph):
        result = await graph.run(
            alert_id="alert-001",
            tenant_id="tenant-A",
            entities={},
        )
        assert result.investigation_id  # UUID should be set

    @pytest.mark.asyncio
    async def test_same_tenant_alert_has_deterministic_investigation_id(
        self, graph, mock_repo
    ):
        first = await graph.run("alert-stable", "tenant-A", {})
        mock_repo.load.return_value = None
        second = await graph.run("alert-stable", "tenant-A", {})
        assert first.investigation_id == second.investigation_id

    @pytest.mark.asyncio
    async def test_duplicate_terminal_alert_returns_existing_state(
        self, graph, mock_repo
    ):
        existing = GraphState(
            investigation_id="existing",
            alert_id="alert-001",
            tenant_id="tenant-A",
            state=InvestigationState.CLOSED,
            classification="true_positive",
        )
        mock_repo.load.return_value = existing

        result = await graph.run("alert-001", "tenant-A", {})

        assert result is existing
        mock_repo.save.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_interrupted_stage_resumes_same_investigation(
        self, graph, mock_repo
    ):
        existing = GraphState(
            investigation_id="existing",
            alert_id="alert-001",
            tenant_id="tenant-A",
            state=InvestigationState.PARSING,
        )
        mock_repo.load.return_value = existing

        result = await graph.run("alert-001", "tenant-A", {})

        assert result.investigation_id == "existing"
        assert any(
            getattr(entry, "action", "") == "resume_interrupted_investigation"
            for entry in result.decision_chain
        )

    @pytest.mark.asyncio
    async def test_decision_chain_populated(self, graph):
        result = await graph.run(
            alert_id="alert-001",
            tenant_id="tenant-A",
            entities={},
        )
        # Should have transition entries for each stage
        assert len(result.decision_chain) >= 3

    @pytest.mark.asyncio
    async def test_persists_final_state(self, graph, mock_repo):
        await graph.run(
            alert_id="alert-001",
            tenant_id="tenant-A",
            entities={},
        )
        mock_repo.save.assert_called()


class TestFPShortCircuit:
    @pytest.mark.asyncio
    async def test_fp_match_closes_early(self, graph, mock_fp):
        mock_fp.check.return_value = FPMatchResult(
            matched=True, pattern_id="FP-001", confidence=0.95
        )

        def apply_sc(state, match):
            state.state = InvestigationState.CLOSED
            state.classification = "false_positive"
            return state

        mock_fp.apply_shortcircuit = apply_sc

        result = await graph.run(
            alert_id="alert-001",
            tenant_id="tenant-A",
            entities={},
            alert_title="Known FP Alert",
        )
        assert result.state == InvestigationState.CLOSED
        assert result.classification == "false_positive"

    @pytest.mark.asyncio
    async def test_no_fp_continues_pipeline(self, graph, mock_fp):
        mock_fp.check.return_value = FPMatchResult(matched=False)
        result = await graph.run(
            alert_id="alert-002",
            tenant_id="tenant-A",
            entities={},
        )
        assert result.state == InvestigationState.CLOSED


class TestHumanApproval:
    @pytest.mark.asyncio
    async def test_awaiting_human_pauses(self, graph, mock_reasoning, mock_fp):
        # Make reasoning return AWAITING_HUMAN
        async def reasoning_execute(state):
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True
            state.classification = "true_positive"
            state.confidence = 0.4
            return state

        mock_reasoning.execute = reasoning_execute

        result = await graph.run(
            alert_id="alert-003",
            tenant_id="tenant-A",
            entities={},
            severity="critical",
        )
        assert result.state == InvestigationState.AWAITING_HUMAN
        assert result.requires_human_approval is True

    @pytest.mark.asyncio
    async def test_resume_approved(self, graph, mock_repo):
        waiting_state = GraphState(
            investigation_id="inv-waiting",
            state=InvestigationState.AWAITING_HUMAN,
            alert_id="alert-003",
        )
        mock_repo.load.return_value = waiting_state

        result = await graph.resume_from_approval("inv-waiting", approved=True)
        assert result is not None
        assert result.state == InvestigationState.CLOSED

    @pytest.mark.asyncio
    async def test_resume_rejected(self, graph, mock_repo):
        waiting_state = GraphState(
            investigation_id="inv-waiting",
            state=InvestigationState.AWAITING_HUMAN,
        )
        mock_repo.load.return_value = waiting_state

        result = await graph.resume_from_approval("inv-waiting", approved=False)
        assert result is not None
        assert result.state == InvestigationState.CLOSED

    @pytest.mark.asyncio
    async def test_resume_not_found(self, graph, mock_repo):
        mock_repo.load.return_value = None
        result = await graph.resume_from_approval("nonexistent", approved=True)
        assert result is None

    @pytest.mark.asyncio
    async def test_resume_wrong_state(self, graph, mock_repo):
        state = GraphState(
            investigation_id="inv-closed",
            state=InvestigationState.CLOSED,
        )
        mock_repo.load.return_value = state
        result = await graph.resume_from_approval("inv-closed", approved=True)
        assert result.state == InvestigationState.CLOSED


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_unrecoverable_error(self, graph, mock_fp):
        # Make IOC extractor fail
        async def fail_execute(state):
            raise RuntimeError("IOC extraction failed")

        graph._ioc.execute = fail_execute

        result = await graph.run(
            alert_id="alert-fail",
            tenant_id="tenant-A",
            entities={},
        )
        assert result.state == InvestigationState.FAILED
        assert any(
            "unrecoverable_error" in str(d.get("action", ""))
            for d in result.decision_chain
        )

    @pytest.mark.asyncio
    async def test_parallel_enrichment_partial_failure(self, graph, mock_fp):
        # Make CTEM fail but others succeed
        async def fail_ctem(state):
            raise RuntimeError("CTEM unavailable")

        graph._ctem.execute = fail_ctem

        result = await graph.run(
            alert_id="alert-partial",
            tenant_id="tenant-A",
            entities={},
        )
        # Should still complete — CTEM failure is non-fatal
        assert result.state == InvestigationState.CLOSED


class TestNoFPModule:
    @pytest.mark.asyncio
    async def test_works_without_fp(self, mock_repo, mock_ioc, mock_enricher,
                                     mock_ctem, mock_atlas, mock_reasoning, mock_response):
        graph = InvestigationGraph(
            repository=mock_repo,
            ioc_extractor=mock_ioc,
            context_enricher=mock_enricher,
            ctem_correlator=mock_ctem,
            atlas_mapper=mock_atlas,
            reasoning_agent=mock_reasoning,
            response_agent=mock_response,
            fp_shortcircuit=None,
        )
        result = await graph.run(
            alert_id="alert-nofp",
            tenant_id="tenant-A",
            entities={},
        )
        assert result.state == InvestigationState.CLOSED
