"""LLM Router data models — Stories 6.1, 12.2, 12.3, 12.4.

Defines tiers, model configs, routing decisions, task context,
fallback registry, and degradation policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from shared.schemas.routing import LLMProvider, ModelConfig


class ModelTier(str, Enum):
    """Four-tier model architecture."""

    TIER_0 = "tier_0"       # Haiku  — fast, cheap
    TIER_1 = "tier_1"       # Sonnet — deep reasoning
    TIER_1_PLUS = "tier_1+" # Opus   — complex / escalation
    TIER_2 = "tier_2"       # Sonnet Batch — offline


# Legacy alias for backward compatibility
AnthropicModelConfig = ModelConfig


# ---- model registry --------------------------------------------------------

MODEL_REGISTRY: dict[ModelTier, ModelConfig] = {
    ModelTier.TIER_0: ModelConfig(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-haiku-4-5-20251001",
        max_context_tokens=200_000,
        cost_per_mtok_input=0.80,
        cost_per_mtok_output=4.0,
    ),
    ModelTier.TIER_1: ModelConfig(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-sonnet-4-5-20250929",
        max_context_tokens=200_000,
        cost_per_mtok_input=3.0,
        cost_per_mtok_output=15.0,
    ),
    ModelTier.TIER_1_PLUS: ModelConfig(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-opus-4-6",
        max_context_tokens=200_000,
        cost_per_mtok_input=15.0,
        cost_per_mtok_output=75.0,
        supports_extended_thinking=True,
    ),
    ModelTier.TIER_2: ModelConfig(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-sonnet-4-5-20250929",
        max_context_tokens=200_000,
        cost_per_mtok_input=1.5,
        cost_per_mtok_output=7.5,
        batch_eligible=True,
    ),
}


# ---- fallback registry (Story 12.3) ----------------------------------------

FALLBACK_REGISTRY: dict[ModelTier, list[ModelConfig]] = {
    ModelTier.TIER_0: [
        ModelConfig(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4o-mini",
            max_context_tokens=128_000,
            cost_per_mtok_input=0.15,
            cost_per_mtok_output=0.60,
        ),
    ],
    ModelTier.TIER_1: [
        ModelConfig(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4o",
            max_context_tokens=128_000,
            cost_per_mtok_input=2.50,
            cost_per_mtok_output=10.0,
        ),
    ],
    ModelTier.TIER_1_PLUS: [
        ModelConfig(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4o",
            max_context_tokens=128_000,
            cost_per_mtok_input=2.50,
            cost_per_mtok_output=10.0,
            supports_extended_thinking=False,
        ),
    ],
    ModelTier.TIER_2: [],  # Batch tier has no fallback
}


# ---- routing data ----------------------------------------------------------

@dataclass
class TaskContext:
    """Input to the router — describes the task to be routed."""

    task_type: str
    context_tokens: int = 0
    time_budget_seconds: int = 30
    alert_severity: str = "medium"
    tenant_tier: str = "standard"
    requires_reasoning: bool = False
    previous_confidence: float | None = None


@dataclass
class RoutingDecision:
    """Output of the router — the selected model and parameters."""

    tier: ModelTier
    model_config: ModelConfig
    max_tokens: int
    temperature: float
    use_extended_thinking: bool = False
    use_prompt_caching: bool = True
    reason: str = ""
    fallback_configs: list[ModelConfig] = field(default_factory=list)
    degradation_level: str = "full_capability"


# ---- default parameters per tier -------------------------------------------

TIER_DEFAULTS: dict[ModelTier, dict[str, int | float]] = {
    ModelTier.TIER_0: {"max_tokens": 2048, "temperature": 0.1},
    ModelTier.TIER_1: {"max_tokens": 8192, "temperature": 0.2},
    ModelTier.TIER_1_PLUS: {"max_tokens": 16384, "temperature": 0.2},
    ModelTier.TIER_2: {"max_tokens": 16384, "temperature": 0.3},
}


# ---- severity → priority queue mapping ------------------------------------

SEVERITY_QUEUE_MAP: dict[str, str] = {
    "critical": "jobs.llm.priority.critical",
    "high": "jobs.llm.priority.high",
    "medium": "jobs.llm.priority.normal",
    "low": "jobs.llm.priority.low",
    "informational": "jobs.llm.priority.low",
}


# ---- degradation levels (Story 12.4, NFR-REL-001 to NFR-REL-005) ----------

class DegradationLevel(str, Enum):
    """Five-level degradation playbook (PRD NFR-REL-001 to NFR-REL-005).

    Level 1 — FULL_CAPABILITY:   All providers healthy; Opus/Sonnet available.
    Level 2 — SECONDARY_ACTIVE:  Primary (Anthropic) down; OpenAI fallback.
    Level 3 — DETERMINISTIC_ONLY: All LLM providers down; IOC/FP/TI matching only.
    Level 4 — SEARCH_ONLY:       Vector DB also down; Redis + Postgres exact-match only.
    Level 5 — PASSTHROUGH_ONLY:  All data stores degraded; raw alert forwarded to queue.
    """

    FULL_CAPABILITY = "full_capability"
    SECONDARY_ACTIVE = "secondary_active"
    DETERMINISTIC_ONLY = "deterministic_only"
    SEARCH_ONLY = "search_only"
    PASSTHROUGH_ONLY = "passthrough_only"


@dataclass
class DegradationPolicy:
    """Policy settings for each degradation level."""

    level: DegradationLevel
    confidence_threshold_override: float = 0.0
    extended_thinking_available: bool = True
    max_tier: ModelTier = ModelTier.TIER_1_PLUS
    alert_ops: bool = False
    # Orchestrator pipeline flags
    llm_available: bool = True
    vector_search_available: bool = True
    graph_reasoning_available: bool = True


DEGRADATION_POLICIES: dict[DegradationLevel, DegradationPolicy] = {
    DegradationLevel.FULL_CAPABILITY: DegradationPolicy(
        level=DegradationLevel.FULL_CAPABILITY,
        confidence_threshold_override=0.0,
        extended_thinking_available=True,
        max_tier=ModelTier.TIER_1_PLUS,
        llm_available=True,
        vector_search_available=True,
        graph_reasoning_available=True,
    ),
    DegradationLevel.SECONDARY_ACTIVE: DegradationPolicy(
        level=DegradationLevel.SECONDARY_ACTIVE,
        confidence_threshold_override=0.95,
        extended_thinking_available=False,
        max_tier=ModelTier.TIER_1,
        alert_ops=True,
        llm_available=True,
        vector_search_available=True,
        graph_reasoning_available=True,
    ),
    DegradationLevel.DETERMINISTIC_ONLY: DegradationPolicy(
        level=DegradationLevel.DETERMINISTIC_ONLY,
        confidence_threshold_override=1.0,
        extended_thinking_available=False,
        max_tier=ModelTier.TIER_0,
        alert_ops=True,
        llm_available=False,
        vector_search_available=True,
        graph_reasoning_available=True,
    ),
    DegradationLevel.SEARCH_ONLY: DegradationPolicy(
        level=DegradationLevel.SEARCH_ONLY,
        confidence_threshold_override=1.0,
        extended_thinking_available=False,
        max_tier=ModelTier.TIER_0,
        alert_ops=True,
        llm_available=False,
        vector_search_available=False,
        graph_reasoning_available=False,
    ),
    DegradationLevel.PASSTHROUGH_ONLY: DegradationPolicy(
        level=DegradationLevel.PASSTHROUGH_ONLY,
        confidence_threshold_override=1.0,
        extended_thinking_available=False,
        max_tier=ModelTier.TIER_0,
        alert_ops=True,
        llm_available=False,
        vector_search_available=False,
        graph_reasoning_available=False,
    ),
}
