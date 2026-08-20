"""Investigation state machine and graph state models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class InvestigationState(str, Enum):
    """Investigation lifecycle states (LangGraph node transitions)."""

    RECEIVED = "received"
    PARSING = "parsing"
    ENRICHING = "enriching"
    REASONING = "reasoning"
    AWAITING_HUMAN = "awaiting_human"
    RESPONDING = "responding"
    CLOSED = "closed"
    FAILED = "failed"


class AgentRole(str, Enum):
    """Roles within the investigation graph."""

    IOC_EXTRACTOR = "ioc_extractor"
    CONTEXT_ENRICHER = "context_enricher"
    REASONING_AGENT = "reasoning_agent"
    RESPONSE_AGENT = "response_agent"
    CTEM_CORRELATOR = "ctem_correlator"
    ATLAS_MAPPER = "atlas_mapper"


@dataclass
class DecisionEntry:
    """Record of a decision point in the investigation workflow.

    Story 14.7 adds ``attestation_status`` for trust model tracking.
    """

    step: str = ""
    agent: str = ""
    action: str = ""
    reasoning: str = ""
    confidence: float = 0.0
    attestation_status: str = ""
    taxonomy_version: str = ""

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like access for backward compatibility with dict entries."""
        return getattr(self, key, default)


class GraphState(BaseModel):
    """Explicit state object persisted to Postgres for each investigation."""

    investigation_id: str
    state: InvestigationState = InvestigationState.RECEIVED
    alert_id: str = ""
    tenant_id: str = ""
    source_context: dict[str, Any] = Field(default_factory=dict)
    entities: dict[str, Any] = Field(default_factory=dict)
    ioc_matches: list[Any] = Field(default_factory=list)
    ueba_context: list[Any] = Field(default_factory=list)
    ctem_exposures: list[Any] = Field(default_factory=list)
    atlas_techniques: list[Any] = Field(default_factory=list)
    similar_incidents: list[Any] = Field(default_factory=list)
    playbook_matches: list[Any] = Field(default_factory=list)
    decision_chain: list[Any] = Field(default_factory=list)
    classification: str = ""
    confidence: float = 0.0
    severity: str = ""
    recommended_actions: list[Any] = Field(default_factory=list)
    requires_human_approval: bool = False
    risk_state: str = "unknown"
    llm_calls: int = 0
    total_cost_usd: float = 0.0
    queries_executed: int = Field(default=0)
    case_facts: dict[str, Any] = Field(default_factory=dict)
