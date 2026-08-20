"""Contract tests for the remote Context Gateway client."""

import httpx
import pytest

from context_gateway.client import ContextGatewayHTTPClient
from context_gateway.gateway import GatewayRequest


@pytest.mark.asyncio
async def test_complete_maps_request_and_response():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(__import__("json").loads(request.content))
        return httpx.Response(
            200,
            json={
                "content": "{\"classification\": \"true_positive\"}",
                "model_id": "model-1",
                "tokens_used": 42,
                "valid": True,
                "validation_errors": [],
                "quarantined_ids": [],
                "injection_detections": [],
                "cost_usd": 0.012,
                "latency_ms": 15.5,
            },
        )

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://gateway",
    )
    client = ContextGatewayHTTPClient("http://gateway/", client=http_client)
    request = GatewayRequest(
        agent_id="reasoning",
        task_type="investigation",
        system_prompt="system",
        user_content="evidence",
        tenant_id="tenant-a",
        use_extended_thinking=True,
    )

    response = await client.complete(request)

    assert captured["tenant_id"] == "tenant-a"
    assert captured["use_extended_thinking"] is True
    assert response.valid is True
    assert response.tokens_used == 42
    assert response.metrics is not None
    assert response.metrics.cost_usd == pytest.approx(0.012)
    await http_client.aclose()


@pytest.mark.asyncio
async def test_health_check_uses_ready_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/ready"
        return httpx.Response(200, json={"status": "ready"})

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://gateway",
    )
    client = ContextGatewayHTTPClient("http://gateway", client=http_client)

    assert await client.health_check() is True
    await http_client.aclose()
