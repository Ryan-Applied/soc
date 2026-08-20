"""IOC Extractor agent — Story 7.2.

Tier 0 (Haiku) extraction of IOCs from normalized entities,
enriched via Redis IOC cache.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from shared.schemas.investigation import GraphState, InvestigationState

logger = logging.getLogger(__name__)

IOC_SYSTEM_PROMPT = (
    "You are a security IOC extractor. Extract all IOCs from the alert entities: "
    "IP addresses, file hashes (MD5/SHA1/SHA256), domains, URLs, and user accounts. "
    "Return JSON: {\"iocs\": [{\"type\": \"ip|hash|domain|url|account\", "
    "\"value\": \"...\"}]}"
)


class IOCExtractorAgent:
    """Extracts IOCs via Haiku and enriches from Redis cache."""

    def __init__(
        self,
        gateway: Any,
        redis_client: Any,
    ) -> None:
        self._gateway = gateway
        self._redis = redis_client

    async def execute(self, state: GraphState) -> GraphState:
        """Extract IOCs and enrich from Redis.

        State transition: RECEIVED → PARSING.
        """
        state.state = InvestigationState.PARSING

        # Call Context Gateway for IOC extraction
        from context_gateway.gateway import GatewayRequest

        request = GatewayRequest(
            agent_id="ioc_extractor",
            task_type="ioc_extraction",
            system_prompt=IOC_SYSTEM_PROMPT,
            user_content=json.dumps(state.entities),
            tenant_id=state.tenant_id,
        )
        response = await self._gateway.complete(request)
        state.llm_calls += 1
        if response.metrics:
            state.total_cost_usd += response.metrics.cost_usd

        # Parse extracted IOCs
        iocs = _parse_ioc_response(response.content)

        # Enrich from Redis
        enriched: list[dict[str, Any]] = []
        for ioc in iocs:
            cached = await self._redis.get_ioc(
                state.tenant_id, ioc["type"], ioc["value"]
            )
            state.queries_executed += 1
            if cached:
                enriched.append({**ioc, **cached})
            else:
                enriched.append(ioc)

        state.ioc_matches = enriched
        return state


def _parse_ioc_response(content: str) -> list[dict[str, Any]]:
    """Parse IOC extraction JSON response."""
    try:
        data = json.loads(content)
        if isinstance(data, dict) and "iocs" in data:
            return data["iocs"]
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return []
