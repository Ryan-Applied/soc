"""Circuit breaker and provider health registry — Stories 12.3, 12.4.

Implements per-provider circuit breaker pattern with three states:
CLOSED (healthy), OPEN (tripped), HALF_OPEN (probing recovery).
Adds degradation level computation for provider outage playbook.
"""

from __future__ import annotations

import time
from enum import Enum

from shared.schemas.routing import LLMProvider

# Re-export for convenience
__all__ = ["CircuitBreaker", "CircuitBreakerState", "InfraBreaker", "ProviderHealthRegistry"]


class CircuitBreakerState(str, Enum):
    """Three-state circuit breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Per-provider circuit breaker with configurable thresholds.

    State machine:
        CLOSED  → OPEN       on ``failure_threshold`` consecutive failures
        OPEN    → HALF_OPEN  after ``recovery_timeout_seconds`` elapsed
        HALF_OPEN → CLOSED   on success (probe passed)
        HALF_OPEN → OPEN     on failure (probe failed)
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._opened_at: float = 0.0

    @property
    def state(self) -> CircuitBreakerState:
        """Current state, with automatic OPEN → HALF_OPEN promotion."""
        if (
            self._state == CircuitBreakerState.OPEN
            and time.monotonic() - self._opened_at > self.recovery_timeout_seconds
        ):
            self._state = CircuitBreakerState.HALF_OPEN
        return self._state

    @property
    def is_available(self) -> bool:
        """True when CLOSED or HALF_OPEN (probe allowed)."""
        return self.state != CircuitBreakerState.OPEN

    def record_success(self) -> None:
        """Record a successful call — reset failures or close breaker."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call — increment counter or re-open breaker."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self._open()
            return
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._open()

    def _open(self) -> None:
        self._state = CircuitBreakerState.OPEN
        self._opened_at = time.monotonic()
        self._failure_count = 0


class InfraBreaker(str, Enum):
    """Infrastructure component identifiers for non-LLM health tracking."""

    VECTOR_DB = "vector_db"    # Qdrant
    GRAPH_DB = "graph_db"      # Neo4j
    REDIS = "redis"
    POSTGRES = "postgres"


class ProviderHealthRegistry:
    """Manages per-provider circuit breakers and infra health flags.

    Tracks LLM providers via per-provider :class:`CircuitBreaker` instances
    and infrastructure components via simple boolean health flags.
    Together these drive the 5-level degradation model (NFR-REL-001 to 005).

    Degradation mapping:
        Level 1 — FULL_CAPABILITY:    Anthropic up
        Level 2 — SECONDARY_ACTIVE:   Anthropic down, OpenAI up
        Level 3 — DETERMINISTIC_ONLY: All LLMs down, vector+graph up
        Level 4 — SEARCH_ONLY:        All LLMs + vector/graph down, Redis/PG up
        Level 5 — PASSTHROUGH_ONLY:   Everything down
    """

    def __init__(self) -> None:
        self._breakers: dict[LLMProvider, CircuitBreaker] = {}
        self._infra_health: dict[InfraBreaker, bool] = {
            InfraBreaker.VECTOR_DB: True,
            InfraBreaker.GRAPH_DB: True,
            InfraBreaker.REDIS: True,
            InfraBreaker.POSTGRES: True,
        }

    def _get(self, provider: LLMProvider) -> CircuitBreaker:
        if provider not in self._breakers:
            self._breakers[provider] = CircuitBreaker()
        return self._breakers[provider]

    def is_available(self, provider: LLMProvider) -> bool:
        """Check if *provider* is considered healthy."""
        return self._get(provider).is_available

    def record_success(self, provider: LLMProvider) -> None:
        """Record a successful call to *provider*."""
        self._get(provider).record_success()

    def record_failure(self, provider: LLMProvider) -> None:
        """Record a failed call to *provider*."""
        self._get(provider).record_failure()

    def set_infra_health(self, component: InfraBreaker, healthy: bool) -> None:
        """Update health status for an infrastructure component."""
        self._infra_health[component] = healthy

    def is_infra_available(self, component: InfraBreaker) -> bool:
        """Check if an infrastructure component is healthy."""
        return self._infra_health.get(component, True)

    def compute_degradation_level(self) -> "DegradationLevel":
        """Compute the current 5-level degradation state (NFR-REL-001 to 005)."""
        from llm_router.models import DegradationLevel

        primary_up = self.is_available(LLMProvider.ANTHROPIC)
        secondary_up = self.is_available(LLMProvider.OPENAI)
        vector_up = self.is_infra_available(InfraBreaker.VECTOR_DB)
        graph_up = self.is_infra_available(InfraBreaker.GRAPH_DB)
        redis_up = self.is_infra_available(InfraBreaker.REDIS)
        pg_up = self.is_infra_available(InfraBreaker.POSTGRES)

        # Level 1: Primary LLM healthy
        if primary_up:
            return DegradationLevel.FULL_CAPABILITY

        # Level 2: Secondary LLM available
        if secondary_up:
            return DegradationLevel.SECONDARY_ACTIVE

        # All LLMs down from here — Level 3, 4, or 5
        # Level 3: IOC/FP deterministic matching — needs Redis + Postgres (+ optionally vector)
        if redis_up and pg_up and (vector_up or graph_up):
            return DegradationLevel.DETERMINISTIC_ONLY

        # Level 4: Only exact-match stores available (Redis + Postgres, no vector/graph)
        if redis_up or pg_up:
            return DegradationLevel.SEARCH_ONLY

        # Level 5: Nothing available — passthrough raw alert to queue
        return DegradationLevel.PASSTHROUGH_ONLY

    def get_policy(self) -> "DegradationPolicy":
        """Return the degradation policy for the current level."""
        from llm_router.models import DEGRADATION_POLICIES

        return DEGRADATION_POLICIES[self.compute_degradation_level()]
