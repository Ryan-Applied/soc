"""Sentinel connectors — Story 4.2.

Two connection modes:
* **Event Hub** — near-real-time via Azure Event Hubs SDK
* **Log Analytics API** — polling via REST (30 s default interval)

Both connectors publish :class:`CanonicalAlert` JSON to the ``alerts.raw``
Kafka topic.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from confluent_kafka import Producer

from sentinel_adapter.adapter import SentinelAdapter
from sentinel_adapter.checkpoint import SentinelCheckpointStore

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL = 30  # seconds
DEFAULT_OVERLAP_SECONDS = 60
MAX_RETRIES = 3
BASE_DELAY = 1  # seconds


async def retry_with_backoff(
    coro_func: Any,
    *args: Any,
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    **kwargs: Any,
) -> Any:
    """Exponential-backoff wrapper: 1 s → 2 s → 4 s."""
    for attempt in range(max_retries):
        try:
            return await coro_func(*args, **kwargs)
        except Exception as exc:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    "Attempt %d/%d failed, retrying in %.1fs: %s",
                    attempt + 1, max_retries, delay, exc,
                )
                await asyncio.sleep(delay)
            else:
                logger.error("All %d attempts failed: %s", max_retries, exc)
                raise


def _canonical_to_bytes(adapter: SentinelAdapter, raw_event: dict[str, Any]) -> tuple[bytes | None, bytes] | None:
    """Map a raw event through the adapter and serialise.

    Returns ``(key_bytes, value_bytes)`` or ``None`` if the event is
    dropped (heartbeat).
    """
    canonical = adapter.to_canonical(raw_event)
    if canonical is None:
        return None

    key = canonical.alert_id.encode("utf-8") if canonical.alert_id else None
    value = json.dumps(canonical.model_dump(), default=str).encode("utf-8")
    return key, value


class SentinelEventHubConnector:
    """Near-real-time Sentinel ingestion via Azure Event Hubs.

    Requires the ``azure-eventhub`` package (optional dependency).
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        event_hub_connection_string: str,
        kafka_bootstrap: str,
        consumer_group: str = "$Default",
    ) -> None:
        self.connection_string = event_hub_connection_string
        self.consumer_group = consumer_group
        self.adapter = SentinelAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._running = False

    async def subscribe(self) -> None:
        """Connect to Event Hub and begin forwarding events."""
        # Import lazily so the rest of the codebase doesn't require azure-eventhub
        from azure.eventhub.aio import EventHubConsumerClient  # type: ignore[import-untyped]

        client = EventHubConsumerClient.from_connection_string(
            self.connection_string,
            consumer_group=self.consumer_group,
        )
        self._running = True

        async with client:
            await client.receive_batch(
                on_event_batch=self._on_event_batch,
                starting_position="-1",
            )

    async def _on_event_batch(self, partition_context: Any, events: list[Any]) -> None:
        for event in events:
            try:
                raw_event = json.loads(event.body_as_str())
                pair = _canonical_to_bytes(self.adapter, raw_event)
                if pair is None:
                    continue
                key, value = pair
                self.producer.produce(topic=self.TOPIC, key=key, value=value)
            except Exception as exc:
                logger.error("Error processing Event Hub event: %s", exc, exc_info=True)

        self.producer.flush(timeout=5)
        await partition_context.update_checkpoint()

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        self.stop()
        self.producer.flush(timeout=5)


class SentinelLogAnalyticsConnector:
    """Polling-based Sentinel ingestion via Log Analytics REST API.

    Requires the ``aiohttp`` package (optional dependency).
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        workspace_id: str,
        credential: Any,
        kafka_bootstrap: str,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        *,
        connector_id: str = "sentinel-default",
        checkpoint_store: SentinelCheckpointStore | None = None,
        overlap_seconds: int = DEFAULT_OVERLAP_SECONDS,
        subscription_id: str = "",
        resource_group: str = "",
        workspace_name: str = "",
    ) -> None:
        self.workspace_id = workspace_id
        self.credential = credential  # Azure TokenCredential
        self.poll_interval = poll_interval
        self.connector_id = connector_id
        self.checkpoint_store = checkpoint_store
        self.overlap_seconds = max(0, overlap_seconds)
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.adapter = SentinelAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._running = False
        self._last_poll_ts: str | None = None
        self.last_success_at: str | None = None
        self.last_error: str | None = None

    async def subscribe(self) -> None:
        """Begin polling loop."""
        if self.checkpoint_store is not None:
            self._last_poll_ts = await self.checkpoint_store.load_watermark(
                self.connector_id
            )
        self._running = True
        logger.info(
            "Log Analytics connector started (workspace=%s, interval=%ds)",
            self.workspace_id, self.poll_interval,
        )
        while self._running:
            try:
                await retry_with_backoff(self._poll_once)
                self.last_success_at = datetime.now(timezone.utc).isoformat()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
                logger.error("Polling failed after retries: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self) -> None:
        import aiohttp  # type: ignore[import-untyped]

        token = self.credential.get_token("https://api.loganalytics.io/.default")
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
        }

        time_filter = "| where TimeGenerated > ago(5m)"
        if self._last_poll_ts:
            watermark = datetime.fromisoformat(
                self._last_poll_ts.replace("Z", "+00:00")
            )
            query_start = watermark - timedelta(seconds=self.overlap_seconds)
            time_filter = f"| where TimeGenerated > datetime({query_start.isoformat()})"

        body = {
            "query": (
                "let LatestIncidents = SecurityIncident "
                "| summarize arg_max(TimeGenerated, *) by IncidentName "
                "| mv-expand SystemAlertId = AlertIds "
                "| project SystemAlertId=tostring(SystemAlertId), IncidentName, "
                "IncidentNumber, IncidentUrl, ProviderIncidentId; "
                "SecurityAlert "
                + time_filter
                + " | join kind=leftouter LatestIncidents on SystemAlertId "
                "| project SystemAlertId, TimeGenerated, AlertName, Description, "
                "Severity=AlertSeverity, Tactics, Techniques, Entities, ProductName, "
                "TenantId, VendorOriginalId, IncidentName, IncidentNumber, "
                "IncidentUrl, ProviderIncidentId | order by TimeGenerated asc"
            ),
        }

        async with aiohttp.ClientSession() as session:
            url = f"https://api.loganalytics.azure.com/v1/workspaces/{self.workspace_id}/query"
            async with session.post(url, json=body, headers=headers) as resp:
                resp.raise_for_status()
                result = await resp.json()

        tables = result.get("tables", [])
        if not tables:
            return

        columns = [c["name"] for c in tables[0].get("columns", [])]
        latest_ts = self._last_poll_ts
        processed: list[tuple[str, str]] = []

        for row in tables[0].get("rows", []):
            raw_event = dict(zip(columns, row))
            raw_event["_aluskort_connector_id"] = self.connector_id
            raw_event["_aluskort_workspace_id"] = self.workspace_id
            raw_event["_aluskort_subscription_id"] = self.subscription_id
            raw_event["_aluskort_resource_group"] = self.resource_group
            raw_event["_aluskort_workspace_name"] = self.workspace_name
            alert_id = str(raw_event.get("SystemAlertId", ""))
            ts = raw_event.get("TimeGenerated", "")
            if ts and (latest_ts is None or ts > latest_ts):
                latest_ts = ts
            if (
                self.checkpoint_store is not None
                and alert_id
                and await self.checkpoint_store.is_processed(
                    self.connector_id, alert_id
                )
            ):
                continue
            pair = _canonical_to_bytes(self.adapter, raw_event)
            if pair is None:
                continue
            key, value = pair
            self.producer.produce(topic=self.TOPIC, key=key, value=value)

            ts = raw_event.get("TimeGenerated", "")
            if alert_id and ts:
                processed.append((alert_id, ts))

        undelivered = self.producer.flush(timeout=5)
        if undelivered:
            raise RuntimeError(f"Kafka flush left {undelivered} Sentinel alerts undelivered")

        if self.checkpoint_store is not None:
            for alert_id, ts in processed:
                await self.checkpoint_store.mark_processed(
                    self.connector_id, alert_id, ts
                )
        if latest_ts:
            self._last_poll_ts = latest_ts
            if self.checkpoint_store is not None:
                await self.checkpoint_store.save_watermark(
                    self.connector_id, latest_ts
                )

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        self.stop()
        self.producer.flush(timeout=5)
