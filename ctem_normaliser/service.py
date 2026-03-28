"""CTEM Normaliser Kafka service — Story 8.6.

Consumes from per-source ctem.raw.* topics, routes to the correct
normaliser, upserts to Postgres, and publishes to ctem.normalized.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from ctem_normaliser.asset_discovery import AssetDiscoveryScheduler
from ctem_normaliser.base import BaseNormaliser
from ctem_normaliser.models import CTEMExposure
from ctem_normaliser.upsert import CTEMRepository
from ctem_normaliser.art import ARTNormaliser
from ctem_normaliser.burp import BurpNormaliser
from ctem_normaliser.garak import GarakNormaliser
from ctem_normaliser.snyk import SnykNormaliser
from ctem_normaliser.wiz import WizNormaliser

logger = logging.getLogger(__name__)

# Topic → normaliser mapping
TOPIC_NORMALISER_MAP: dict[str, type[BaseNormaliser]] = {
    "ctem.raw.wiz": WizNormaliser,
    "ctem.raw.snyk": SnykNormaliser,
    "ctem.raw.garak": GarakNormaliser,
    "ctem.raw.art": ARTNormaliser,
    "ctem.raw.burp": BurpNormaliser,
}

NORMALISED_TOPIC = "ctem.normalized"
DLQ_TOPIC = "ctem.normalized.dlq"

SUBSCRIBED_TOPICS = [
    "ctem.raw.wiz",
    "ctem.raw.snyk",
    "ctem.raw.garak",
    "ctem.raw.art",
    "ctem.raw.burp",
    "ctem.raw.custom",
]


class CTEMNormaliserService:
    """Kafka consumer service that normalises CTEM findings."""

    def __init__(
        self,
        repository: CTEMRepository,
        kafka_consumer: Any | None = None,
        kafka_producer: Any | None = None,
        neo4j_client: Any | None = None,
        audit_producer: Any | None = None,
        pg_pool: Any | None = None,
        redis_client: Any | None = None,
    ) -> None:
        self._repo = repository
        self._consumer = kafka_consumer
        self._producer = kafka_producer
        self._neo4j = neo4j_client
        self._audit = audit_producer
        self._normalisers: dict[str, BaseNormaliser] = {}
        self._init_normalisers()
        self._discovery_scheduler: AssetDiscoveryScheduler | None = None
        if pg_pool is not None and kafka_producer is not None:
            self._discovery_scheduler = AssetDiscoveryScheduler(
                pg_pool=pg_pool,
                kafka_producer=kafka_producer,
                redis_client=redis_client,
            )

    def _init_normalisers(self) -> None:
        """Instantiate normalisers with optional dependencies."""
        self._normalisers = {
            "ctem.raw.wiz": WizNormaliser(neo4j_client=self._neo4j),
            "ctem.raw.snyk": SnykNormaliser(),
            "ctem.raw.garak": GarakNormaliser(),
            "ctem.raw.art": ARTNormaliser(),
            "ctem.raw.burp": BurpNormaliser(),
        }

    async def start_background_tasks(self) -> list[asyncio.Task]:  # type: ignore[type-arg]
        """Start long-running background tasks (e.g. asset discovery scheduler).

        Returns the list of created :class:`asyncio.Task` objects so the caller
        can cancel them on shutdown.
        """
        tasks: list[asyncio.Task] = []  # type: ignore[type-arg]
        if self._discovery_scheduler is not None:
            task = asyncio.create_task(
                self._discovery_scheduler.run_forever(),
                name="ctem-asset-discovery",
            )
            tasks.append(task)
            logger.info("Asset discovery scheduler background task started")
        return tasks

    def get_normaliser(self, topic: str) -> BaseNormaliser | None:
        """Get the normaliser for a given topic."""
        return self._normalisers.get(topic)

    async def process_message(
        self,
        topic: str,
        raw_data: dict[str, Any],
    ) -> CTEMExposure | None:
        """Normalise a single message, upsert, and publish.

        Returns the normalised exposure, or None on failure.
        """
        normaliser = self.get_normaliser(topic)
        if normaliser is None:
            # Unsupported tool — route to generic handling or DLQ
            logger.warning("No normaliser for topic %s", topic)
            await self._send_to_dlq(topic, raw_data, "unsupported_topic")
            return None

        try:
            exposure = normaliser.normalise(raw_data)
        except Exception as exc:
            logger.error(
                "Normalisation failed for %s: %s", topic, exc,
                exc_info=True,
            )
            await self._send_to_dlq(topic, raw_data, str(exc))
            return None

        # Upsert to Postgres
        try:
            await self._repo.upsert(exposure)
        except Exception as exc:
            logger.error(
                "Upsert failed for %s: %s", exposure.exposure_key, exc,
                exc_info=True,
            )
            await self._send_to_dlq(topic, raw_data, f"upsert_failed: {exc}")
            return None

        # Publish to normalised topic
        await self._publish_normalised(exposure)

        # Emit audit event
        self._emit_audit(exposure)

        return exposure

    async def _publish_normalised(self, exposure: CTEMExposure) -> None:
        """Publish normalised exposure to ctem.normalized topic."""
        if self._producer is None:
            return
        from dataclasses import asdict
        try:
            await self._producer.produce(
                NORMALISED_TOPIC, asdict(exposure)
            )
        except Exception:
            logger.warning(
                "Failed to publish normalised exposure %s",
                exposure.exposure_key, exc_info=True,
            )

    def _emit_audit(self, exposure: CTEMExposure) -> None:
        """Emit ctem.exposure_scored audit event (fire-and-forget)."""
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=getattr(exposure, "tenant_id", "system"),
                event_type="ctem.exposure_scored",
                event_category="decision",
                actor_type="system",
                actor_id="ctem-normaliser",
                context={
                    "exposure_key": exposure.exposure_key,
                    "severity": getattr(exposure, "severity", ""),
                },
            )
        except Exception:
            logger.warning("Audit emit failed for ctem.exposure_scored", exc_info=True)

    async def _send_to_dlq(
        self,
        topic: str,
        raw_data: dict[str, Any],
        error: str,
    ) -> None:
        """Send failed message to dead letter queue."""
        if self._producer is None:
            return
        try:
            await self._producer.produce(
                DLQ_TOPIC,
                {
                    "source_topic": topic,
                    "raw_data": raw_data,
                    "error": error,
                },
            )
        except Exception:
            logger.warning("Failed to send to DLQ", exc_info=True)


# ---------------------------------------------------------------------------
# Kafka consumer runner
# ---------------------------------------------------------------------------

class CTEMConsumerRunner:
    """Wraps CTEMNormaliserService with a confluent-kafka consumer loop."""

    def __init__(
        self,
        service: CTEMNormaliserService,
        kafka_bootstrap: str,
        consumer_group: str = "aluskort.ctem-normaliser",
    ) -> None:
        from confluent_kafka import Consumer as KConsumer, KafkaError, Producer as KProducer

        self._service = service
        self._consumer = KConsumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": consumer_group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self._running = False

    def start(self) -> None:
        self._consumer.subscribe(SUBSCRIBED_TOPICS)
        self._running = True
        logger.info("CTEM normaliser subscribed to %s", SUBSCRIBED_TOPICS)

    def stop(self) -> None:
        self._running = False

    async def run(self) -> None:
        """Async consumer loop."""
        import asyncio as _asyncio
        from confluent_kafka import KafkaError

        self.start()

        # Start background tasks (asset discovery scheduler, etc.)
        bg_tasks = await self._service.start_background_tasks()
        logger.info("CTEM normaliser service running")

        try:
            await self._run_consumer_loop()
        finally:
            for task in bg_tasks:
                task.cancel()
                try:
                    await task
                except _asyncio.CancelledError:
                    pass

    async def _run_consumer_loop(self) -> None:
        """Inner consumer poll loop."""
        from confluent_kafka import KafkaError

        while self._running:
            msg = self._consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error("Consumer error: %s", msg.error())
                continue

            try:
                raw_data = json.loads(msg.value().decode("utf-8"))
                topic = msg.topic()
                await self._service.process_message(topic, raw_data)
                self._consumer.commit(message=msg)
            except Exception as exc:
                logger.error("CTEM processing failed: %s", exc, exc_info=True)
                self._consumer.commit(message=msg)

    def close(self) -> None:
        self.stop()
        self._consumer.close()


def main() -> None:
    """Entry point for ``python -m ctem_normaliser.service``."""
    import asyncio
    import os
    import signal

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    postgres_dsn = os.environ.get("POSTGRES_DSN", "")

    # Repository
    db = None
    if postgres_dsn:
        try:
            from shared.db.postgres import PostgresClient
            db = PostgresClient(dsn=postgres_dsn)
        except Exception:
            logger.warning("Postgres unavailable — running without persistence")

    repo = CTEMRepository(postgres_client=db)
    service = CTEMNormaliserService(repository=repo)
    runner = CTEMConsumerRunner(service=service, kafka_bootstrap=kafka_bootstrap)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, runner.stop)
        except NotImplementedError:
            signal.signal(sig, lambda *_: runner.stop())

    try:
        loop.run_until_complete(runner.run())
    finally:
        runner.close()
        loop.close()
        logger.info("CTEM normaliser service stopped")


if __name__ == "__main__":
    main()
