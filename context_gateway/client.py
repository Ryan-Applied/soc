"""HTTP client for the Context Gateway service boundary."""

from __future__ import annotations

from typing import Any

import httpx

from context_gateway.anthropic_client import APICallMetrics
from context_gateway.gateway import GatewayRequest, GatewayResponse


class ContextGatewayHTTPClient:
    """Expose the remote Context Gateway through the in-process gateway API."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def complete(self, request: GatewayRequest) -> GatewayResponse:
        response = await self._client.post(
            f"{self._base_url}/v1/complete",
            json={
                "agent_id": request.agent_id,
                "task_type": request.task_type,
                "system_prompt": request.system_prompt,
                "user_content": request.user_content,
                "output_schema": request.output_schema,
                "tenant_id": request.tenant_id,
                "use_extended_thinking": request.use_extended_thinking,
            },
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        metrics = APICallMetrics(
            cost_usd=float(data.get("cost_usd", 0.0)),
            latency_ms=float(data.get("latency_ms", 0.0)),
            model_id=str(data.get("model_id", "")),
        )
        return GatewayResponse(
            content=str(data.get("content", "")),
            model_id=str(data.get("model_id", "")),
            tokens_used=int(data.get("tokens_used", 0)),
            valid=bool(data.get("valid", False)),
            raw_output=str(data.get("content", "")),
            validation_errors=list(data.get("validation_errors", [])),
            quarantined_ids=list(data.get("quarantined_ids", [])),
            injection_detections=list(data.get("injection_detections", [])),
            metrics=metrics,
        )

    async def health_check(self) -> bool:
        try:
            response = await self._client.get(f"{self._base_url}/ready")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
