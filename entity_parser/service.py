"""Entity Parser Kafka service — Stories 3.2 & 3.3.

Consumes ``alerts.raw``, parses entities, and produces to
``alerts.normalized``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from shared.schemas.alert import CanonicalAlert
from shared.schemas.entity import NormalizedEntity

from entity_parser.parser import parse_alert_entities

logger = logging.getLogger(__name__)

TOPIC_RAW = "alerts.raw"
TOPIC_NORMALIZED = "alerts.normalized"
TOPIC_DLQ = "alerts.raw.dlq"
DEFAULT_GROUP = "aluskort.entity-parser"


def _entity_to_dict(entity: NormalizedEntity) -> dict[str, Any]:
    """Serialize a NormalizedEntity for JSON transport."""
    return {
        "entity_type": entity.entity_type.value,
        "primary_value": entity.primary_value,
        "properties": entity.properties,
        "confidence": entity.confidence,
        "source_id": entity.source_id,
    }


class EntityParserService:
    """Microservice that consumes raw alerts and produces normalised alerts."""

    def __init__(
        self,
        kafka_bootstrap: str,
        consumer_group: str = DEFAULT_GROUP,
    ) -> None:
        self.consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": consumer_group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self.producer = Producer({
            "bootstrap.servers": kafka_bootstrap,
        })
        self._running = False
        self.audit_producer = None

    def _emit_audit_classified(self, alert_data: dict[str, Any]) -> None:
        """Emit alert.classified audit event (fire-and-forget)."""
        if self.audit_producer is None:
            return
        try:
            self.audit_producer.emit(
                tenant_id=alert_data.get("tenant_id", "unknown"),
                event_type="alert.classified",
                event_category="decision",
                actor_type="agent",
                actor_id="entity-parser",
                alert_id=alert_data.get("alert_id", ""),
            )
        except Exception:
            logger.warning("Audit emit failed for alert.classified", exc_info=True)

    def _emit_audit_injection(
        self, tenant_id: str, alert_id: str, detection_count: int,
    ) -> None:
        """Emit injection.detected audit event (fire-and-forget)."""
        if self.audit_producer is None:
            return
        try:
            self.audit_producer.emit(
                tenant_id=tenant_id,
                event_type="injection.detected",
                event_category="security",
                actor_type="system",
                actor_id="entity-parser",
                severity="warning",
                alert_id=alert_id,
                context={"detection_count": detection_count},
            )
        except Exception:
            logger.warning("Audit emit failed for injection.detected", exc_info=True)

    def start(self) -> None:
        """Subscribe and begin processing."""
        self.consumer.subscribe([TOPIC_RAW])
        self._running = True
        logger.info("Entity parser subscribed to %s", TOPIC_RAW)

    def stop(self) -> None:
        """Signal the run loop to exit."""
        self._running = False

    def close(self) -> None:
        """Flush producer and close consumer."""
        self.stop()
        self.producer.flush(timeout=5)
        self.consumer.close()

    def process_message(self, raw_value: bytes) -> dict[str, Any]:
        """Deserialize, parse entities, and return enriched alert dict.

        Raises ``ValueError`` if the message cannot be deserialized into
        a ``CanonicalAlert``.
        """
        alert_data: dict[str, Any] = json.loads(raw_value.decode("utf-8"))

        # Validate against CanonicalAlert schema
        CanonicalAlert(**alert_data)

        entities_raw = alert_data.get("entities_raw", "")
        raw_payload = alert_data.get("raw_payload")

        entities = parse_alert_entities(entities_raw, raw_payload)

        alert_data["parsed_entities"] = {
            "accounts": [_entity_to_dict(e) for e in entities.accounts],
            "hosts": [_entity_to_dict(e) for e in entities.hosts],
            "ips": [_entity_to_dict(e) for e in entities.ips],
            "files": [_entity_to_dict(e) for e in entities.files],
            "processes": [_entity_to_dict(e) for e in entities.processes],
            "urls": [_entity_to_dict(e) for e in entities.urls],
            "dns_records": [_entity_to_dict(e) for e in entities.dns_records],
            "file_hashes": [_entity_to_dict(e) for e in entities.file_hashes],
            "mailboxes": [_entity_to_dict(e) for e in entities.mailboxes],
            "other": [_entity_to_dict(e) for e in entities.other],
            "raw_iocs": entities.raw_iocs,
            "parse_errors": entities.parse_errors,
        }
        return alert_data

    def _send_to_dlq(self, raw_value: bytes, error: str) -> None:
        """Route a bad message to the dead-letter queue."""
        dlq_payload = json.dumps({
            "original": raw_value.decode("utf-8", errors="replace"),
            "error": error,
        }).encode("utf-8")
        self.producer.produce(topic=TOPIC_DLQ, value=dlq_payload)
        self.producer.flush(timeout=5)

    def run(self) -> None:
        """Main consumer loop — blocks until ``stop()`` is called."""
        self.start()
        logger.info("Entity parser service running")

        while self._running:
            msg = self.consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error("Consumer error: %s", msg.error())
                continue

            raw_value = msg.value()

            try:
                enriched = self.process_message(raw_value)
            except Exception as exc:
                logger.error("Failed to parse alert: %s", exc, exc_info=True)
                self._send_to_dlq(raw_value, str(exc))
                self.consumer.commit(message=msg)
                continue

            alert_id = enriched.get("alert_id", "")
            try:
                self.producer.produce(
                    topic=TOPIC_NORMALIZED,
                    key=alert_id.encode("utf-8") if alert_id else None,
                    value=json.dumps(enriched).encode("utf-8"),
                )
                self.producer.flush(timeout=5)
                self.consumer.commit(message=msg)
                pe = enriched.get("parsed_entities", {})
                logger.info(
                    "Parsed alert %s: %d IOCs, %d errors",
                    alert_id,
                    len(pe.get("raw_iocs", [])),
                    len(pe.get("parse_errors", [])),
                )
            except KafkaException as exc:
                logger.error("Producer failed for alert %s: %s", alert_id, exc)
                # Do NOT commit — allow reprocessing on next poll


def main() -> None:
    """Entry point for ``python -m entity_parser.service``."""
    import os
    import signal

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    svc = EntityParserService(kafka_bootstrap=kafka_bootstrap)
    from shared.worker_health import WorkerHealthServer
    health = WorkerHealthServer(
        "entity-parser", int(os.environ.get("HEALTH_PORT", "8082"))
    )
    health.start()

    # Audit producer (optional)
    try:
        from shared.audit.producer import AuditProducer
        svc.audit_producer = AuditProducer(
            kafka_bootstrap=kafka_bootstrap, service_name="entity-parser",
        )
    except Exception:
        logger.warning("Audit producer unavailable")

    def _shutdown(*_: Any) -> None:
        svc.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        health.mark_ready()
        svc.run()
    finally:
        health.close()
        svc.close()
        logger.info("Entity parser service stopped")


if __name__ == "__main__":
    main()
