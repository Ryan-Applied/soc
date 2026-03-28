"""Context Gateway — ties together all sub-components.

Provides :class:`GatewayRequest` / :class:`GatewayResponse` data models
and the :class:`ContextGateway` orchestrator that runs the full pipeline:

    sanitise → redact → build prompt → call LLM → validate → strip → deanonymise
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from context_gateway.anthropic_client import APICallMetrics, AluskortAnthropicClient
from context_gateway.evidence_builder import EvidenceBlock
from context_gateway.injection_classifier import (
    InjectionAction,
    InjectionClassification,
    RegexInjectionClassifier,
)
from context_gateway.injection_detector import sanitise_input
from context_gateway.output_validator import validate_output
from context_gateway.pii_redactor import RedactionMap, deanonymise_text, redact_pii
from context_gateway.prompt_builder import build_cached_system_blocks, build_structured_prompt
from context_gateway.spend_guard import SpendGuard
from context_gateway.summarizer import transform_content

logger = logging.getLogger(__name__)


@dataclass
class GatewayRequest:
    """Incoming request to the Context Gateway."""

    agent_id: str
    task_type: str
    system_prompt: str
    user_content: str
    output_schema: Optional[dict[str, Any]] = None
    tenant_id: str = "default"
    use_extended_thinking: bool = False


@dataclass
class GatewayResponse:
    """Response returned by the Context Gateway."""

    content: str
    model_id: str
    tokens_used: int
    valid: bool
    raw_output: str = ""
    validation_errors: list[str] = field(default_factory=list)
    quarantined_ids: list[str] = field(default_factory=list)
    metrics: Optional[APICallMetrics] = None
    injection_detections: list[str] = field(default_factory=list)


class ContextGateway:
    """Centralised LLM sanitisation + output validation service.

    REM-C03: integrates layered injection defense:
    - Injection classifier (regex + optional LLM second opinion)
    - Lossy summarization (no redaction markers / tuning oracle)
    - Structured evidence isolation (XML-delimited untrusted data)
    """

    def __init__(
        self,
        client: AluskortAnthropicClient,
        spend_guard: SpendGuard | None = None,
        known_technique_ids: set[str] | None = None,
        audit_producer: Any | None = None,
        taxonomy_version: str = "",
    ) -> None:
        self.client = client
        self.spend_guard = spend_guard or SpendGuard()
        self.known_technique_ids = known_technique_ids
        self.audit_producer = audit_producer
        self.taxonomy_version = taxonomy_version
        self._injection_classifier = RegexInjectionClassifier()

    async def complete(self, request: GatewayRequest) -> GatewayResponse:
        """Run the full gateway pipeline.

        1. Check spend budget.
        2. Classify injection risk (regex fast path, no redaction markers).
        3. Transform content based on classification (pass/summarize/quarantine).
        4. Redact PII.
        5. Build structured prompt with XML evidence isolation.
        6. Call Anthropic API (skip if quarantined).
        7. Validate output.
        7a. Store raw_output (before stripping).
        7b. Strip quarantined IDs (deny-by-default).
        7c. Publish quarantine events to audit.events.
        8. Deanonymise response.
        """
        # 1 — spend guard
        self.spend_guard.check_budget()

        # 2 — injection classification (REM-C03 Part B: no tuning oracle)
        classification = self._injection_classifier.classify(
            alert_title="",
            alert_description=request.user_content,
            entities_json="",
        )
        detections: list[str] = []
        if classification.action != InjectionAction.PASS:
            detections.append(
                f"injection_risk:{classification.risk.value}"
                f"(confidence={classification.confidence:.2f})"
            )

        # 2a — emit quarantine audit event for malicious content
        if classification.action == InjectionAction.QUARANTINE:
            self._emit_injection_quarantined(request, classification)
            return GatewayResponse(
                content="Content quarantined for security review.",
                model_id="",
                tokens_used=0,
                valid=False,
                raw_output="",
                validation_errors=["Content quarantined: injection detected"],
                quarantined_ids=[],
                metrics=None,
                injection_detections=detections,
            )

        # 3 — transform content (REM-C03 Part C: lossy summarize, no markers)
        transformed_content = transform_content(
            request.user_content, classification.action.value
        )

        # 4 — PII redaction
        redacted_content, redaction_map = redact_pii(transformed_content)

        # 5 — structured prompt with XML evidence isolation (REM-C03 Part A)
        evidence_block = EvidenceBlock.wrap_evidence(
            alert_title="",
            alert_description=redacted_content,
            entities_json="",
        )
        system_blocks = build_cached_system_blocks(request.system_prompt)
        messages = [{"role": "user", "content": evidence_block}]

        # 6 — LLM call
        response_text, metrics = await self.client.complete(
            system=system_blocks,
            messages=messages,
            use_extended_thinking=request.use_extended_thinking,
        )

        # 7 — output validation
        valid, errors, quarantined = validate_output(
            response_text,
            known_technique_ids=self.known_technique_ids,
            output_schema=request.output_schema,
        )

        # 7a — preserve raw LLM output before any modifications
        raw_output = response_text

        # 7b — deny-by-default: strip quarantined IDs from content
        stripped_text = _strip_quarantined_ids(response_text, quarantined)

        # 7c — publish quarantine events via AuditProducer (fire-and-forget)
        if quarantined and self.audit_producer is not None:
            for tid in quarantined:
                self._emit_technique_quarantined(
                    technique_id=tid,
                    tenant_id=request.tenant_id,
                    agent_id=request.agent_id,
                    task_type=request.task_type,
                )

        # 7d — emit routing.tier_selected audit event with full LLM context
        self._emit_routing_tier_selected(request, metrics)

        # 8 — deanonymise
        final_text = deanonymise_text(stripped_text, redaction_map)

        # record cost
        self.spend_guard.record(
            cost_usd=metrics.cost_usd,
            model_id=metrics.model_id,
            task_type=request.task_type,
            tenant_id=request.tenant_id,
        )

        return GatewayResponse(
            content=final_text,
            model_id=metrics.model_id,
            tokens_used=metrics.input_tokens + metrics.output_tokens,
            valid=valid,
            raw_output=raw_output,
            validation_errors=errors,
            quarantined_ids=quarantined,
            metrics=metrics,
            injection_detections=detections,
        )

    def _emit_injection_quarantined(
        self, request: GatewayRequest, classification: InjectionClassification,
    ) -> None:
        """Emit injection.quarantined audit event (fire-and-forget)."""
        if self.audit_producer is None:
            return
        try:
            self.audit_producer.emit(
                tenant_id=request.tenant_id,
                event_type="injection.quarantined",
                event_category="security",
                actor_type="agent",
                actor_id=request.agent_id,
                context={
                    "risk": classification.risk.value,
                    "confidence": classification.confidence,
                    "reason": classification.reason,
                    "task_type": request.task_type,
                },
            )
        except Exception:
            logger.warning("Audit emit failed for injection.quarantined", exc_info=True)

    def _emit_technique_quarantined(
        self,
        *,
        technique_id: str,
        tenant_id: str,
        agent_id: str,
        task_type: str,
    ) -> None:
        """Emit technique.quarantined via AuditProducer (fire-and-forget)."""
        if self.audit_producer is None:
            return
        try:
            self.audit_producer.emit(
                tenant_id=tenant_id,
                event_type="technique.quarantined",
                event_category="security",
                actor_type="agent",
                actor_id=agent_id,
                context={
                    "technique_id": technique_id,
                    "task_type": task_type,
                    "taxonomy_version": self.taxonomy_version,
                },
            )
        except Exception:
            logger.warning(
                "Audit emit failed for technique.quarantined %s", technique_id,
                exc_info=True,
            )

    def _emit_routing_tier_selected(
        self, request: GatewayRequest, metrics: APICallMetrics
    ) -> None:
        """Emit routing.tier_selected with full LLM context (fire-and-forget)."""
        if self.audit_producer is None:
            return
        try:
            import hashlib
            prompt_hash = hashlib.sha256(request.system_prompt.encode()).hexdigest()[:16]
            self.audit_producer.emit(
                tenant_id=request.tenant_id,
                event_type="routing.tier_selected",
                event_category="decision",
                actor_type="agent",
                actor_id=request.agent_id,
                context={
                    "llm_provider": "anthropic",
                    "llm_model_id": metrics.model_id,
                    "llm_input_tokens": metrics.input_tokens,
                    "llm_output_tokens": metrics.output_tokens,
                    "llm_cost_usd": metrics.cost_usd,
                    "llm_latency_ms": metrics.latency_ms,
                    "llm_system_prompt_hash": prompt_hash,
                    "task_type": request.task_type,
                },
            )
        except Exception:
            logger.warning("Audit emit failed for routing.tier_selected", exc_info=True)


def _strip_quarantined_ids(text: str, quarantined: list[str]) -> str:
    """Remove quarantined technique IDs from text (deny-by-default).

    Replaces each quarantined ID with an empty string so it cannot drive
    automation (playbook selection, severity escalation, FP matching).
    """
    if not quarantined:
        return text
    for tid in quarantined:
        # F7: use word-boundary regex to avoid stripping substrings
        text = re.sub(r'\b' + re.escape(tid) + r'\b', '', text)
    return text
