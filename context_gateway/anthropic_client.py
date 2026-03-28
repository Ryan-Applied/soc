"""Anthropic API client wrapper — Story 5.5.

Async wrapper around ``anthropic.AsyncAnthropic`` with:
* Exponential-backoff retry for 429 / 5xx errors (4xx not retried).
* Per-call ``APICallMetrics`` (tokens, cost, latency).
* Streaming support (returns async iterator of text chunks).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BASE_DELAY = 1.0  # seconds

# Approximate per-token pricing (USD) — update when pricing changes.
# These are defaults; callers can override via model_pricing.
DEFAULT_PRICING: dict[str, dict[str, float]] = {
    "claude-sonnet-4-5-20250929": {
        "input": 3.0 / 1_000_000,
        "output": 15.0 / 1_000_000,
        "cache_read": 0.30 / 1_000_000,
        "cache_write": 3.75 / 1_000_000,
    },
    "claude-haiku-4-5-20251001": {
        "input": 0.80 / 1_000_000,
        "output": 4.0 / 1_000_000,
        "cache_read": 0.08 / 1_000_000,
        "cache_write": 1.0 / 1_000_000,
    },
}


@dataclass
class APICallMetrics:
    """Metrics captured for every Anthropic API call."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    model_id: str = ""


def compute_cost(metrics: APICallMetrics, pricing: dict[str, float] | None = None) -> float:
    """Calculate USD cost from token counts and pricing table."""
    if pricing is None:
        pricing = DEFAULT_PRICING.get(metrics.model_id, {})
    cost = (
        metrics.input_tokens * pricing.get("input", 0)
        + metrics.output_tokens * pricing.get("output", 0)
        + metrics.cache_read_tokens * pricing.get("cache_read", 0)
        + metrics.cache_write_tokens * pricing.get("cache_write", 0)
    )
    return round(cost, 6)


class AluskortAnthropicClient:
    """Async Anthropic client with retry, metrics, and streaming."""

    def __init__(
        self,
        api_key: str,
        default_model: str = "claude-sonnet-4-5-20250929",
        max_retries: int = MAX_RETRIES,
        base_delay: float = BASE_DELAY,
    ) -> None:
        # Lazy import so tests don't require the anthropic package
        import anthropic  # type: ignore[import-untyped]

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self.default_model = default_model
        self.max_retries = max_retries
        self.base_delay = base_delay

    async def complete(
        self,
        *,
        system: str | list[dict[str, Any]],
        messages: list[dict[str, Any]],
        model: str | None = None,
        max_tokens: int = 4096,
        use_extended_thinking: bool = False,
    ) -> tuple[str, APICallMetrics]:
        """Send a completion request with retry on transient errors.

        Returns ``(response_text, metrics)``.

        When *use_extended_thinking* is True, the Anthropic extended thinking
        feature is enabled (budget_tokens=8000) and temperature is forced to 1
        as required by the API.  Response text is extracted only from ``text``
        blocks; ``thinking`` blocks are discarded.
        """
        import anthropic  # type: ignore[import-untyped]

        model = model or self.default_model

        # Build extra kwargs for extended thinking (Anthropic requirement:
        # thinking param + temperature must be exactly 1).
        extra_kwargs: dict[str, Any] = {}
        if use_extended_thinking:
            extra_kwargs["thinking"] = {"type": "enabled", "budget_tokens": 8000}
            extra_kwargs["temperature"] = 1

        for attempt in range(self.max_retries):
            t0 = time.monotonic()
            try:
                response = await self._client.messages.create(
                    model=model,
                    system=system,
                    messages=messages,
                    max_tokens=max_tokens,
                    **extra_kwargs,
                )
                latency = (time.monotonic() - t0) * 1000

                metrics = APICallMetrics(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
                    cache_write_tokens=getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
                    latency_ms=latency,
                    model_id=model,
                )
                metrics.cost_usd = compute_cost(metrics)

                # Extract only text blocks; skip thinking blocks when extended
                # thinking is enabled (they contain internal chain-of-thought
                # that must not be returned to callers).
                if use_extended_thinking:
                    text = "".join(
                        block.text
                        for block in response.content
                        if getattr(block, "type", None) == "text"
                    )
                else:
                    text = response.content[0].text if response.content else ""
                return text, metrics

            except anthropic.RateLimitError:
                if attempt < self.max_retries - 1:
                    delay = self.base_delay * (2 ** attempt)
                    logger.warning("Rate limited (429), retrying in %.1fs", delay)
                    await asyncio.sleep(delay)
                else:
                    raise
            except anthropic.APIStatusError as exc:
                if exc.status_code >= 500 and attempt < self.max_retries - 1:
                    delay = self.base_delay * (2 ** attempt)
                    logger.warning("Server error %d, retrying in %.1fs", exc.status_code, delay)
                    await asyncio.sleep(delay)
                else:
                    raise  # 4xx errors are not retried

        # Unreachable, but keeps mypy happy
        raise RuntimeError("Exhausted retries")  # pragma: no cover

    async def stream(
        self,
        *,
        system: str | list[dict[str, Any]],
        messages: list[dict[str, Any]],
        model: str | None = None,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a completion, yielding text chunks."""
        model = model or self.default_model

        async with self._client.messages.stream(
            model=model,
            system=system,
            messages=messages,
            max_tokens=max_tokens,
        ) as stream:
            async for text in stream.text_stream:
                yield text

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.close()
