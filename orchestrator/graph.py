"""Investigation Graph — Story 7.8.

State machine executor: consumes alerts, runs agent nodes in
topological order, handles parallelism, branching, and persistence.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Optional

from shared.schemas.investigation import (
    AgentRole,
    DecisionEntry,
    GraphState,
    InvestigationState,
)
from orchestrator.persistence import InvestigationRepository
from orchestrator.fp_shortcircuit import FPShortCircuit
from orchestrator.agents.response_agent import ApprovalGate
from shared.schemas.event_taxonomy import EventTaxonomy
from llm_router.models import DEGRADATION_POLICIES, DegradationLevel, DegradationPolicy

logger = logging.getLogger(__name__)


class InvestigationGraph:
    """Executes the full investigation lifecycle as a state machine.

    Graph topology::

        RECEIVED → IOC_EXTRACTOR → FP_CHECK
            ├→ CLOSED (if FP match)
            └→ ENRICHING (parallel: CONTEXT_ENRICHER, CTEM_CORRELATOR, ATLAS_MAPPER)
                → REASONING_AGENT
                    ├→ RESPONDING → CLOSED
                    └→ AWAITING_HUMAN
                        ├→ RESPONDING (approved) → CLOSED
                        └→ CLOSED (rejected / timeout)
    """

    def __init__(
        self,
        *,
        repository: InvestigationRepository,
        ioc_extractor: Any,
        context_enricher: Any,
        ctem_correlator: Any,
        atlas_mapper: Any,
        reasoning_agent: Any,
        response_agent: Any,
        fp_shortcircuit: FPShortCircuit | None = None,
        audit_producer: Any | None = None,
        shadow_mode_manager: Any | None = None,
        health_registry: Any | None = None,
    ) -> None:
        self._repo = repository
        self._ioc = ioc_extractor
        self._enricher = context_enricher
        self._ctem = ctem_correlator
        self._atlas = atlas_mapper
        self._reasoning = reasoning_agent
        self._response = response_agent
        self._fp = fp_shortcircuit
        self._audit = audit_producer
        self._shadow = shadow_mode_manager
        self._health = health_registry  # ProviderHealthRegistry for 5-level degradation

    def _get_degradation_policy(self) -> DegradationPolicy:
        """Return the current degradation policy (5-level, NFR-REL-001 to 005)."""
        if self._health is None:
            return DEGRADATION_POLICIES[DegradationLevel.FULL_CAPABILITY]
        level = self._health.compute_degradation_level()
        return DEGRADATION_POLICIES[level]

    async def run(
        self,
        alert_id: str,
        tenant_id: str,
        entities: dict[str, Any],
        alert_title: str = "",
        severity: str = "medium",
    ) -> GraphState:
        """Execute the full investigation pipeline.

        Returns the final GraphState.
        """
        investigation_id = str(uuid.uuid4())
        state = GraphState(
            investigation_id=investigation_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            entities=entities,
            severity=severity,
        )

        try:
            state = await self._execute_pipeline(state, alert_title)
        except Exception as exc:
            logger.error(
                "Investigation %s failed: %s", investigation_id, exc,
                exc_info=True,
            )
            state.state = InvestigationState.FAILED
            state.decision_chain.append({
                "agent": "graph",
                "action": "unrecoverable_error",
                "error": str(exc),
            })

        # Final persist
        await self._repo.save(state)
        return state

    async def _execute_pipeline(
        self, state: GraphState, alert_title: str
    ) -> GraphState:
        """Execute all pipeline stages respecting the 5-level degradation policy."""
        policy = self._get_degradation_policy()

        # Level 5 — PASSTHROUGH_ONLY: nothing is available; forward raw alert and exit
        if policy.level.value == "passthrough_only":
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True
            state.decision_chain.append(DecisionEntry(
                step="degradation_check",
                agent="orchestrator",
                action="passthrough_mode",
                reasoning="All infrastructure degraded — alert forwarded to analyst queue",
            ))
            self._emit_degraded(state, policy.level.value)
            return state

        # Stage 1: IOC Extraction (RECEIVED → PARSING)
        state = await self._repo.transition(
            state, InvestigationState.PARSING,
            agent=AgentRole.IOC_EXTRACTOR.value,
            action="start_ioc_extraction",
        )
        self._emit_state_changed(state, "received", "parsing")
        state = await self._ioc.execute(state)

        # Stage 1.5: FP Short-Circuit (Redis-backed — available up to Level 4)
        if self._fp is not None:
            fp_result = await self._fp.check(state, alert_title)
            if fp_result.matched:
                state = self._fp.apply_shortcircuit(state, fp_result)
                self._emit_auto_closed(state, fp_result.pattern_id, fp_result.confidence)
                return state

        # Level 4 — SEARCH_ONLY: exact-match only; skip vector search + LLM reasoning
        if policy.level.value == "search_only":
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True
            state.decision_chain.append(DecisionEntry(
                step="degradation_check",
                agent="orchestrator",
                action="search_only_mode",
                reasoning="LLM and vector DB degraded — deterministic match only; escalating to analyst",
            ))
            self._emit_degraded(state, policy.level.value)
            return state

        # Stage 2: Parallel Enrichment (PARSING → ENRICHING)
        state = await self._repo.transition(
            state, InvestigationState.ENRICHING,
            agent="graph",
            action="start_enrichment",
        )
        self._emit_state_changed(state, "parsing", "enriching")

        # Level 3 — DETERMINISTIC_ONLY: run context enricher (Redis/PG) only; skip vector/graph
        if not policy.vector_search_available or not policy.graph_reasoning_available:
            enricher_task = self._enricher.execute(state)
            # CTEM and ATLAS require vector/graph — skip them in deterministic mode
            results = await asyncio.gather(enricher_task, return_exceptions=True)
            state = self._merge_parallel_results(state, [
                results[0],
                Exception("skipped: deterministic_only mode"),
                Exception("skipped: deterministic_only mode"),
            ])
            state.decision_chain.append(DecisionEntry(
                step="degradation_check",
                agent="orchestrator",
                action="deterministic_only_mode",
                reasoning=f"Degradation level {policy.level.value}: vector/graph search skipped",
            ))
            self._emit_degraded(state, policy.level.value)
        else:
            enricher_task = self._enricher.execute(state)
            ctem_task = self._ctem.execute(state)
            atlas_task = self._atlas.execute(state)

            results = await asyncio.gather(
                enricher_task, ctem_task, atlas_task,
                return_exceptions=True,
            )
            state = self._merge_parallel_results(state, results)

        self._emit_enriched(state)

        # Level 3 — DETERMINISTIC_ONLY: skip LLM reasoning; escalate to human
        if not policy.llm_available:
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True
            state.decision_chain.append(DecisionEntry(
                step="degradation_check",
                agent="orchestrator",
                action="no_llm_escalation",
                reasoning="LLM unavailable — IOC/FP matching complete; escalating to analyst for reasoning",
            ))
            self._emit_escalated(state)
            return state

        # Stage 3: Reasoning (ENRICHING → REASONING)
        state = await self._repo.transition(
            state, InvestigationState.REASONING,
            agent=AgentRole.REASONING_AGENT.value,
            action="start_reasoning",
        )
        self._emit_state_changed(state, "enriching", "reasoning")
        state = await self._reasoning.execute(state)

        # Trust constraint: if ALL ATLAS detections are untrusted, force human review
        state = self._apply_trust_constraint(state)

        # Stage 4: Branch — RESPONDING or AWAITING_HUMAN
        if state.state == InvestigationState.AWAITING_HUMAN:
            self._emit_escalated(state)
            await self._repo.save(state)
            return state

        # Stage 5: Shadow mode check — if active, log but don't execute
        if self._shadow is not None and await self._shadow.is_shadow_active(
            state.tenant_id
        ):
            state.decision_chain.append(DecisionEntry(
                step="shadow_mode",
                agent="orchestrator",
                action="shadow_decision_logged",
                reasoning="Shadow mode active — decision logged, not executed",
                confidence=state.confidence,
            ))
            await self._shadow.record_shadow_decision(
                tenant_id=state.tenant_id,
                rule_family=state.classification or "",
                shadow_decision=state.classification or "unknown",
                shadow_confidence=state.confidence,
                investigation_id=state.investigation_id,
            )
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True
            self._emit_escalated(state)
            return state

        # Stage 6: Response (RESPONDING → CLOSED)
        state = await self._repo.transition(
            state, InvestigationState.RESPONDING,
            agent=AgentRole.RESPONSE_AGENT.value,
            action="start_response",
        )
        self._emit_state_changed(state, "reasoning", "responding")
        state = await self._response.execute(state)

        return state

    def _merge_parallel_results(
        self, state: GraphState, results: list[Any]
    ) -> GraphState:
        """Merge results from parallel enrichment agents."""
        enricher_result, ctem_result, atlas_result = results

        if isinstance(enricher_result, GraphState):
            state.ioc_matches = enricher_result.ioc_matches
            state.ueba_context = enricher_result.ueba_context
            state.similar_incidents = enricher_result.similar_incidents
            state.risk_state = enricher_result.risk_state
            state.queries_executed += enricher_result.queries_executed
        elif isinstance(enricher_result, Exception):
            logger.warning("Context enricher failed: %s", enricher_result)

        if isinstance(ctem_result, GraphState):
            state.ctem_exposures = ctem_result.ctem_exposures
            state.queries_executed += ctem_result.queries_executed
        elif isinstance(ctem_result, Exception):
            logger.warning("CTEM correlator failed: %s", ctem_result)

        if isinstance(atlas_result, GraphState):
            state.atlas_techniques = atlas_result.atlas_techniques
            state.queries_executed += atlas_result.queries_executed
        elif isinstance(atlas_result, Exception):
            logger.warning("ATLAS mapper failed: %s", atlas_result)

        return state

    # ── Trust constraint ────────────────────────────────────────

    def _apply_trust_constraint(self, state: GraphState) -> GraphState:
        """Block auto-close/auto-escalation when ALL evidence is untrusted.

        If every ATLAS detection result carries ``telemetry_trust_level ==
        "untrusted"`` and there is at least one detection, force the
        investigation to ``AWAITING_HUMAN`` so a human must review.
        Records the attestation status in the decision chain.
        """
        atlas = state.atlas_techniques
        if not atlas:
            return state

        # Check if all detections are untrusted
        all_untrusted = all(
            (t.get("telemetry_trust_level") if isinstance(t, dict) else getattr(t, "telemetry_trust_level", "trusted"))
            == "untrusted"
            for t in atlas
        )

        if all_untrusted:
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True
            state.decision_chain.append(DecisionEntry(
                step="trust_constraint",
                agent="orchestrator",
                action="force_human_review",
                reasoning="All ATLAS detections based on untrusted telemetry",
                attestation_status="untrusted_only",
            ))
            logger.info(
                "Investigation %s forced to human review: all detections untrusted",
                state.investigation_id,
            )
        else:
            # Record attestation for mixed/trusted cases
            attestation_values = set()
            for t in atlas:
                if isinstance(t, dict):
                    val = t.get("attestation_status", "")
                else:
                    val = getattr(t, "attestation_status", "")
                if val:
                    attestation_values.add(val)
            if attestation_values:
                state.decision_chain.append(DecisionEntry(
                    step="trust_assessment",
                    agent="orchestrator",
                    action="trust_verified",
                    reasoning="Mixed or trusted telemetry sources present",
                    attestation_status=",".join(sorted(attestation_values)),
                ))

        return state

    # ── Audit helpers (fire-and-forget) ─────────────────────────

    def _emit_degraded(self, state: GraphState, level: str) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type="investigation.degraded_mode",
                event_category="decision",
                actor_type="agent",
                actor_id="orchestrator",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
                context={"degradation_level": level},
            )
        except Exception:
            logger.warning("Audit emit failed for investigation.degraded_mode", exc_info=True)

    def _emit_state_changed(self, state: GraphState, from_state: str, to_state: str) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type="investigation.state_changed",
                event_category="decision",
                actor_type="agent",
                actor_id="orchestrator",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
                context={"from_state": from_state, "to_state": to_state},
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for investigation.state_changed", exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for investigation.state_changed", exc_info=True)

    def _emit_auto_closed(self, state: GraphState, pattern_id: str, confidence: float) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type="alert.auto_closed",
                event_category="decision",
                actor_type="agent",
                actor_id="fp_short_circuit",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
                context={"pattern_id": pattern_id, "confidence": confidence},
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for alert.auto_closed", exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for alert.auto_closed", exc_info=True)

    def _emit_enriched(self, state: GraphState) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type="investigation.enriched",
                event_category="decision",
                actor_type="agent",
                actor_id="orchestrator",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for investigation.enriched", exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for investigation.enriched", exc_info=True)

    def _emit_escalated(self, state: GraphState) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type="alert.escalated",
                event_category="decision",
                actor_type="agent",
                actor_id="orchestrator",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for alert.escalated", exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for alert.escalated", exc_info=True)

    async def resume_from_approval(
        self,
        investigation_id: str,
        approved: bool,
    ) -> GraphState | None:
        """Resume an investigation after human approval decision.

        F1: Uses ApprovalGate to determine next transition based on
        severity-aware timeout behavior (escalate vs close).
        """
        state = await self._repo.load(investigation_id)
        if state is None:
            logger.error("Investigation %s not found", investigation_id)
            return None

        if state.state != InvestigationState.AWAITING_HUMAN:
            logger.warning(
                "Investigation %s not awaiting approval (state=%s)",
                investigation_id, state.state.value,
            )
            return state

        # F1: instantiate ApprovalGate with investigation severity
        gate = ApprovalGate(severity=state.severity)
        state = gate.resolve(state, approved=approved)

        if state.state == InvestigationState.RESPONDING:
            # Approved — continue to response execution
            state = await self._repo.transition(
                state, InvestigationState.RESPONDING,
                agent="human",
                action="approval_granted",
            )
            state = await self._response.execute(state)
        elif state.state == InvestigationState.CLOSED:
            # Medium/low timeout → close
            state = await self._repo.transition(
                state, InvestigationState.CLOSED,
                agent="human",
                action="approval_rejected",
            )
        else:
            # Critical/high timeout with escalate behavior — stays AWAITING_HUMAN
            if gate.timeout_behavior == "escalate" and not approved:
                self._emit_approval_escalated(state)
            await self._repo.save(state)
            return state

        await self._repo.save(state)
        return state

    def _emit_approval_escalated(self, state: GraphState) -> None:
        """Emit approval.escalated event when critical/high timeout escalates."""
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type=EventTaxonomy.APPROVAL_ESCALATED.value,
                event_category="approval",
                actor_type="system",
                actor_id="orchestrator",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
                context={
                    "severity": state.severity,
                    "classification": state.classification,
                },
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for approval.escalated", exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for approval.escalated", exc_info=True)
