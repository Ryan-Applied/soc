"""Tests for AuditProducer integration in Orchestrator — Story 13.8, Task 2."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.graph import InvestigationGraph
from orchestrator.fp_shortcircuit import FPMatchResult, FPShortCircuit


def _make_graph(audit_producer=None):
    """Create InvestigationGraph with mocked agents and optional AuditProducer."""
    repo = AsyncMock()
    repo.load = AsyncMock(return_value=None)
    repo.transition = AsyncMock(side_effect=lambda state, new_state, **kw: _set_state(state, new_state))
    repo.save = AsyncMock()

    ioc = AsyncMock()
    ioc.execute = AsyncMock(side_effect=lambda s: s)

    enricher = AsyncMock()
    enricher.execute = AsyncMock(side_effect=lambda s: s)

    ctem = AsyncMock()
    ctem.execute = AsyncMock(side_effect=lambda s: s)

    atlas = AsyncMock()
    atlas.execute = AsyncMock(side_effect=lambda s: s)

    reasoning = AsyncMock()
    reasoning.execute = AsyncMock(side_effect=lambda s: s)

    response = AsyncMock()
    response.execute = AsyncMock(side_effect=lambda s: _close_state(s))

    graph = InvestigationGraph(
        repository=repo,
        ioc_extractor=ioc,
        context_enricher=enricher,
        ctem_correlator=ctem,
        atlas_mapper=atlas,
        reasoning_agent=reasoning,
        response_agent=response,
        audit_producer=audit_producer,
    )
    return graph, repo


def _set_state(state, new_state):
    state.state = new_state
    return state


def _close_state(state):
    state.state = InvestigationState.CLOSED
    return state


class TestOrchestratorAudit:
    """AC-2: investigation.state_changed emitted at every graph edge."""

    @pytest.mark.asyncio
    async def test_state_changed_emitted_per_edge(self):
        """State transitions emit investigation.state_changed audit events."""
        audit = MagicMock()
        graph, repo = _make_graph(audit_producer=audit)

        state = await graph.run("alert-1", "t1", {}, alert_title="Test")

        # Should have emitted for each transition
        emit_calls = [c for c in audit.emit.call_args_list
                      if c[1].get("event_type") == "investigation.state_changed"]
        assert len(emit_calls) >= 3  # PARSING, ENRICHING, REASONING, RESPONDING

    @pytest.mark.asyncio
    async def test_auto_closed_emitted_on_fp_shortcircuit(self):
        """FP short-circuit emits alert.auto_closed."""
        audit = MagicMock()
        fp = AsyncMock(spec=FPShortCircuit)
        fp.check = AsyncMock(return_value=FPMatchResult(matched=True, pattern_id="fp-1", confidence=0.95))
        fp.apply_shortcircuit = MagicMock(side_effect=lambda s, m: _fp_close(s, m))

        repo = AsyncMock()
        repo.load = AsyncMock(return_value=None)
        repo.transition = AsyncMock(side_effect=lambda state, new_state, **kw: _set_state(state, new_state))
        repo.save = AsyncMock()

        graph = InvestigationGraph(
            repository=repo,
            ioc_extractor=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            context_enricher=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            ctem_correlator=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            atlas_mapper=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            reasoning_agent=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            response_agent=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            fp_shortcircuit=fp,
            audit_producer=audit,
        )

        state = await graph.run("alert-2", "t1", {}, alert_title="FP Test")

        auto_closed = [c for c in audit.emit.call_args_list
                       if c[1].get("event_type") == "alert.auto_closed"]
        assert len(auto_closed) == 1
        assert auto_closed[0][1]["context"]["pattern_id"] == "fp-1"

    @pytest.mark.asyncio
    async def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: graph works without audit_producer."""
        graph, repo = _make_graph(audit_producer=None)
        state = await graph.run("alert-3", "t1", {}, alert_title="Test")
        assert state.state == InvestigationState.CLOSED

    @pytest.mark.asyncio
    async def test_enriched_emitted_after_enrichment(self):
        """investigation.enriched is emitted after parallel enrichment."""
        audit = MagicMock()
        graph, repo = _make_graph(audit_producer=audit)

        state = await graph.run("alert-4", "t1", {}, alert_title="Test")

        enriched = [c for c in audit.emit.call_args_list
                    if c[1].get("event_type") == "investigation.enriched"]
        assert len(enriched) == 1

    @pytest.mark.asyncio
    async def test_escalated_emitted_on_awaiting_human(self):
        """alert.escalated is emitted when investigation reaches AWAITING_HUMAN."""
        audit = MagicMock()
        repo = AsyncMock()
        repo.load = AsyncMock(return_value=None)
        repo.transition = AsyncMock(side_effect=lambda state, new_state, **kw: _set_state(state, new_state))
        repo.save = AsyncMock()

        def _escalate(s):
            s.state = InvestigationState.AWAITING_HUMAN
            return s

        graph = InvestigationGraph(
            repository=repo,
            ioc_extractor=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            context_enricher=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            ctem_correlator=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            atlas_mapper=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            reasoning_agent=AsyncMock(execute=AsyncMock(side_effect=_escalate)),
            response_agent=AsyncMock(execute=AsyncMock(side_effect=lambda s: s)),
            audit_producer=audit,
        )

        state = await graph.run("alert-5", "t1", {}, alert_title="Escalation")

        escalated = [c for c in audit.emit.call_args_list
                     if c[1].get("event_type") == "alert.escalated"]
        assert len(escalated) == 1

    @pytest.mark.asyncio
    async def test_audit_emit_failure_does_not_block_pipeline(self):
        """Fire-and-forget: audit failures don't affect the pipeline."""
        audit = MagicMock()
        audit.emit.side_effect = Exception("Kafka down")
        graph, repo = _make_graph(audit_producer=audit)

        state = await graph.run("alert-6", "t1", {}, alert_title="Test")
        assert state.state == InvestigationState.CLOSED


def _fp_close(state, match):
    state.state = InvestigationState.CLOSED
    state.classification = "false_positive"
    state.confidence = match.confidence
    return state
