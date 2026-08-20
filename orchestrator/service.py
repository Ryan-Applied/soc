"""Orchestrator Kafka service — consumes normalised alerts and runs investigations.

Consumes from ``alerts.normalized``, runs the full investigation graph
(IOC extraction → FP check → enrichment → reasoning → response),
and publishes results to ``investigations.completed``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from dataclasses import dataclass
from typing import Any

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

logger = logging.getLogger(__name__)

TOPIC_NORMALIZED = "alerts.normalized"
TOPIC_COMPLETED = "investigations.completed"
TOPIC_DLQ = "alerts.normalized.dlq"
CONSUMER_GROUP = "aluskort.orchestrator"


@dataclass
class OrchestratorRuntime:
    """Live dependencies owned by the orchestrator process."""

    graph: Any
    postgres: Any
    redis: Any
    qdrant: Any
    gateway: Any

    async def close(self) -> None:
        await self.gateway.close()
        await self.redis.close()
        await self.postgres.close()
        self.qdrant.close()


class OrchestratorService:
    """Kafka consumer that drives the investigation graph."""

    def __init__(
        self,
        kafka_bootstrap: str,
        graph: Any,
        consumer_group: str = CONSUMER_GROUP,
    ) -> None:
        self._consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": consumer_group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self._producer = Producer({
            "bootstrap.servers": kafka_bootstrap,
        })
        self._graph = graph
        self._running = False

    def start(self) -> None:
        self._consumer.subscribe([TOPIC_NORMALIZED])
        self._running = True
        logger.info("Orchestrator subscribed to %s", TOPIC_NORMALIZED)

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        self.stop()
        self._producer.flush(timeout=5)
        self._consumer.close()

    async def process_message(self, raw_value: bytes) -> dict[str, Any]:
        """Deserialize alert and run investigation graph."""
        alert_data: dict[str, Any] = json.loads(raw_value.decode("utf-8"))

        alert_id = alert_data.get("alert_id", "")
        tenant_id = alert_data.get("tenant_id", "default")
        entities = alert_data.get("parsed_entities", alert_data.get("entities", {}))
        severity = alert_data.get("severity", "medium")
        alert_title = alert_data.get("title", alert_data.get("alert_name", ""))
        source_context = alert_data.get("source_context", {})

        state = await self._graph.run(
            alert_id=alert_id,
            tenant_id=tenant_id,
            entities=entities,
            alert_title=alert_title,
            severity=severity,
            source_context=source_context,
        )

        return {
            "investigation_id": state.investigation_id,
            "alert_id": state.alert_id,
            "classification": state.classification,
            "confidence": state.confidence,
            "severity": state.severity,
            "state": state.state.value,
            "llm_calls": state.llm_calls,
            "total_cost_usd": state.total_cost_usd,
            "requires_human_approval": state.requires_human_approval,
            "source_context": state.source_context,
        }

    def _send_to_dlq(self, raw_value: bytes, error: str) -> None:
        dlq_payload = json.dumps({
            "original": raw_value.decode("utf-8", errors="replace"),
            "error": error,
        }).encode("utf-8")
        self._producer.produce(topic=TOPIC_DLQ, value=dlq_payload)
        self._producer.flush(timeout=5)

    async def run(self) -> None:
        """Main consumer loop — blocks until stop() is called."""
        self.start()
        logger.info("Orchestrator service running")

        while self._running:
            msg = self._consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error("Consumer error: %s", msg.error())
                continue

            raw_value = msg.value()

            try:
                result = await self.process_message(raw_value)
            except Exception as exc:
                logger.error("Investigation failed: %s", exc, exc_info=True)
                self._send_to_dlq(raw_value, str(exc))
                self._consumer.commit(message=msg)
                continue

            # Publish completed investigation
            inv_id = result.get("investigation_id", "")
            try:
                self._producer.produce(
                    topic=TOPIC_COMPLETED,
                    key=inv_id.encode("utf-8") if inv_id else None,
                    value=json.dumps(result).encode("utf-8"),
                )
                self._producer.flush(timeout=5)
                self._consumer.commit(message=msg)
                logger.info(
                    "Investigation %s completed: %s (confidence=%.2f)",
                    inv_id, result.get("classification"), result.get("confidence", 0),
                )
            except KafkaException as exc:
                logger.error("Producer failed for %s: %s", inv_id, exc)


async def _build_runtime(kafka_bootstrap: str) -> OrchestratorRuntime:
    """Wire the graph to live services, failing startup on missing dependencies."""
    from orchestrator.graph import InvestigationGraph
    from orchestrator.persistence import InvestigationRepository

    from orchestrator.agents.ioc_extractor import IOCExtractorAgent
    from orchestrator.agents.context_enricher import ContextEnricherAgent
    from orchestrator.agents.ctem_correlator import CTEMCorrelatorAgent
    from orchestrator.agents.atlas_mapper import ATLASMapperAgent
    from orchestrator.agents.reasoning_agent import ReasoningAgent
    from orchestrator.agents.response_agent import ResponseAgent

    postgres_dsn = os.environ.get("POSTGRES_DSN", "")
    if not postgres_dsn:
        raise RuntimeError("POSTGRES_DSN is required")

    context_gateway_url = os.environ.get("CONTEXT_GATEWAY_URL", "")
    if not context_gateway_url:
        raise RuntimeError("CONTEXT_GATEWAY_URL is required")

    from context_gateway.client import ContextGatewayHTTPClient
    from shared.db.postgres import PostgresClient
    from shared.db.redis_cache import RedisClient
    from shared.db.vector import QdrantWrapper

    db = PostgresClient(dsn=postgres_dsn, min_size=1, max_size=10)
    redis_client = RedisClient(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
    )
    qdrant_client = QdrantWrapper(
        host=os.environ.get("QDRANT_HOST", "localhost"),
        port=int(os.environ.get("QDRANT_PORT", "6333")),
        grpc_port=int(os.environ.get("QDRANT_GRPC_PORT", "6334")),
    )
    gateway = ContextGatewayHTTPClient(context_gateway_url)
    db_connected = False
    redis_connected = False

    try:
        await db.connect()
        db_connected = True
        await redis_client.connect()
        redis_connected = True
        if not await asyncio.to_thread(qdrant_client.health_check):
            raise RuntimeError("Qdrant health check failed")
        if not await gateway.health_check():
            raise RuntimeError("Context Gateway readiness check failed")
    except Exception:
        await gateway.close()
        if redis_connected:
            await redis_client.close()
        if db_connected:
            await db.close()
        qdrant_client.close()
        raise

    # --- Audit ---
    audit = None
    try:
        from shared.audit.producer import AuditProducer
        audit = AuditProducer(kafka_bootstrap=kafka_bootstrap, service_name="orchestrator")
    except Exception:
        logger.warning("Audit producer unavailable")

    # --- Persistence & Agents ---
    repo = InvestigationRepository(postgres_client=db)
    ioc = IOCExtractorAgent(gateway=gateway, redis_client=redis_client)
    enricher = ContextEnricherAgent(
        redis_client=redis_client,
        postgres_client=db,
        qdrant_client=qdrant_client,
    )
    ctem = CTEMCorrelatorAgent(postgres_client=db)
    atlas = ATLASMapperAgent(postgres_client=db, qdrant_client=qdrant_client)
    reasoning = ReasoningAgent(gateway=gateway)
    response = ResponseAgent(postgres_client=db, audit_producer=audit)

    # --- FP short-circuit ---
    from orchestrator.fp_shortcircuit import FPShortCircuit
    fp = FPShortCircuit(redis_client=redis_client)

    graph = InvestigationGraph(
        repository=repo,
        ioc_extractor=ioc,
        context_enricher=enricher,
        ctem_correlator=ctem,
        atlas_mapper=atlas,
        reasoning_agent=reasoning,
        response_agent=response,
        fp_shortcircuit=fp,
        audit_producer=audit,
    )

    return OrchestratorRuntime(
        graph=graph,
        postgres=db,
        redis=redis_client,
        qdrant=qdrant_client,
        gateway=gateway,
    )


def main() -> None:
    """Entry point for ``python -m orchestrator.service``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runtime = loop.run_until_complete(_build_runtime(kafka_bootstrap))
    service = OrchestratorService(
        kafka_bootstrap=kafka_bootstrap,
        graph=runtime.graph,
    )
    from shared.worker_health import WorkerHealthServer
    health = WorkerHealthServer(
        "orchestrator", int(os.environ.get("HEALTH_PORT", "8081"))
    )
    health.start()

    # Graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, service.stop)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, lambda *_: service.stop())

    try:
        health.mark_ready()
        loop.run_until_complete(service.run())
    finally:
        health.close()
        service.close()
        loop.run_until_complete(runtime.close())
        loop.close()
        logger.info("Orchestrator service stopped")


if __name__ == "__main__":
    main()
