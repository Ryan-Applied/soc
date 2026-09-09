# Service Catalogue

This document describes every service in the ALUSKORT platform, including dependencies, APIs, Kafka topics, database access, configuration, and resource requirements.

---

## 1. Entity Parser

| Property | Value |
|----------|-------|
| **Package** | `entity_parser/` |
| **Entry Point** | `python -m entity_parser.service` |
| **Description** | Consumes raw alerts from SIEM adapters, extracts structured entities (IPs, hosts, accounts, hashes, URLs, processes), normalises them into `CanonicalAlert` schema, and publishes to `alerts.normalized`. |
| **Owner** | Platform Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | SIEM Adapters | Kafka (`alerts.raw`) |
| Downstream | Orchestrator | Kafka (`alerts.normalized`) |
| Infrastructure | PostgreSQL | TCP/5432 |
| Infrastructure | Kafka | TCP/9092 |

### Kafka Topics

| Topic | Direction | Schema |
|-------|-----------|--------|
| `alerts.raw` | Consumer | Raw SIEM alert JSON |
| `alerts.normalized` | Producer | `CanonicalAlert` JSON |
| `alerts.raw.dlq` | Producer | Failed parse payloads |

### Database Tables

| Table | Access |
|-------|--------|
| `taxonomy_ids` | Read (entity type validation) |

### API Endpoints

None (pure Kafka consumer/producer).

### Health Check

| Endpoint | Method |
|----------|--------|
| `/health` | GET |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka/Redpanda bootstrap address |
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 2 | -- |

---

## 2. Orchestrator

| Property | Value |
|----------|-------|
| **Package** | `orchestrator/` |
| **Entry Point** | `python -m orchestrator.service` |
| **Description** | Consumes normalised alerts and executes the investigation state machine. Coordinates 6 agents (IOC Extractor, Context Enricher, CTEM Correlator, ATLAS Mapper, Reasoning Agent, Response Agent). Manages FP short-circuit, kill switches, shadow mode, and human approval gates. |
| **Owner** | Platform Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | Entity Parser | Kafka (`alerts.normalized`) |
| Downstream | Context Gateway | HTTP/8030 |
| Downstream | Dashboard | Kafka (`audit.events`) |
| Infrastructure | PostgreSQL | TCP/5432 |
| Infrastructure | Kafka | TCP/9092 |
| Infrastructure | Redis | TCP/6379 |
| Infrastructure | Qdrant | TCP/6333 |
| Infrastructure | Neo4j | TCP/7687 |

### Kafka Topics

| Topic | Direction | Schema |
|-------|-----------|--------|
| `alerts.normalized` | Consumer | `CanonicalAlert` |
| `incidents.enriched` | Producer | Enriched investigation state |
| `actions.pending` | Producer | Response actions awaiting execution |
| `audit.events` | Producer | Audit trail events |
| `knowledge.incident.stored` | Producer | Closed investigation memory |
| `knowledge.fp.approved` | Producer | FP pattern approvals |

### Database Tables

| Table | Access |
|-------|--------|
| `investigations` (state table) | Read/Write |
| `fp_patterns` | Read |
| `incident_memory` | Read/Write |
| `playbooks` | Read |
| `mitre_techniques` | Read |
| `threat_intel_iocs` | Read |
| `org_context` | Read |
| `ctem_exposures` | Read |

### Health Check

| Endpoint | Method |
|----------|--------|
| `/health` | GET |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka bootstrap address |
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `QDRANT_HOST` | Yes | Qdrant vector DB host |
| `REDIS_HOST` | Yes | Redis host |
| `NEO4J_URI` | Yes | Neo4j bolt URI |
| `CONTEXT_GATEWAY_URL` | Yes | Context Gateway base URL |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 500m | 1000m |
| Memory | 512Mi | 1Gi |
| Replicas (prod) | 2 | -- |

---

## 3. Context Gateway

| Property | Value |
|----------|-------|
| **Package** | `context_gateway/` |
| **Entry Point** | `uvicorn context_gateway.api:app --host 0.0.0.0 --port 8030` |
| **Description** | Centralised LLM interaction service. Runs a 9-stage pipeline: sanitise input, classify injection risk, transform content, redact PII, build structured prompt with XML evidence isolation, call Anthropic API, validate output, strip quarantined technique IDs, deanonymise response. Enforces spend budgets. |
| **Owner** | Security Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | Orchestrator, LLM Router | HTTP/8030 |
| Downstream | Anthropic API | HTTPS |
| Infrastructure | PostgreSQL | TCP/5432 |

### Kafka Topics

| Topic | Direction | Schema |
|-------|-----------|--------|
| `audit.events` | Producer | Security and routing audit events |

### Database Tables

| Table | Access |
|-------|--------|
| `taxonomy_ids` | Read (output validation allowlist) |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/complete` | Submit an LLM completion request |
| GET | `/v1/spend` | Query current spend metrics |
| GET | `/health` | Service health |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key |
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `PORT` | No | Listen port (default: 8030) |
| `MONTHLY_SPEND_HARD_CAP` | No | Hard spend cap in USD (default: 1000) |
| `MONTHLY_SPEND_SOFT_ALERT` | No | Soft spend alert in USD (default: 500) |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 500m | 1000m |
| Memory | 512Mi | 1Gi |
| Replicas (prod) | 2 | -- |

---

## 4. LLM Router

| Property | Value |
|----------|-------|
| **Package** | `llm_router/` |
| **Entry Point** | `uvicorn llm_router.api:app --host 0.0.0.0 --port 8031` |
| **Description** | Routes LLM tasks to the optimal model tier based on task type, severity, context size, time budget, and previous confidence. Provides health-aware fallback to OpenAI when Anthropic is unavailable. Tracks provider selection metrics and degradation levels. |
| **Owner** | Platform Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | Orchestrator | HTTP/8031 |
| Downstream | Context Gateway | HTTP/8030 |

### Kafka Topics

None directly consumed or produced.

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/route` | Route a task to optimal model tier |
| GET | `/v1/models` | List available models and tiers |
| GET | `/v1/health-status` | Provider health and degradation level |
| GET | `/health` | Service health |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `CONTEXT_GATEWAY_URL` | Yes | Context Gateway base URL |
| `PORT` | No | Listen port (default: 8031) |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 1 | -- |

---

## 5. CTEM Normaliser

| Property | Value |
|----------|-------|
| **Package** | `ctem_normaliser/` |
| **Entry Point** | `python -m ctem_normaliser.service` |
| **Description** | Consumes raw vulnerability/exposure findings from security scanners (Wiz, Snyk, Garak, ART), normalises them into `CTEMExposure` records with consequence-weighted severity scoring and SLA deadline computation, and upserts into PostgreSQL. |
| **Owner** | Security Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | External Scanners | Kafka (`ctem.raw.*`) |
| Downstream | Orchestrator | Kafka (`ctem.normalized`) |
| Infrastructure | PostgreSQL | TCP/5432 |
| Infrastructure | Kafka | TCP/9092 |

### Kafka Topics

| Topic | Direction | Schema |
|-------|-----------|--------|
| `ctem.raw.wiz` | Consumer | Wiz vulnerability JSON |
| `ctem.raw.snyk` | Consumer | Snyk vulnerability JSON |
| `ctem.raw.garak` | Consumer | Garak LLM probe results |
| `ctem.raw.art` | Consumer | Adversarial Robustness Toolbox results |
| `ctem.raw.burp` | Consumer | Burp Suite scan results |
| `ctem.raw.custom` | Consumer | Custom scanner results |
| `ctem.normalized` | Producer | `CTEMExposure` JSON |
| `ctem.normalized.dlq` | Producer | Failed normalisation payloads |

### Database Tables

| Table | Access |
|-------|--------|
| `ctem_exposures` | Read/Write (upsert) |
| `ctem_validations` | Read/Write |
| `ctem_remediations` | Read/Write |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka bootstrap address |
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 2 | -- |

---

## 6. Dashboard

| Property | Value |
|----------|-------|
| **Package** | `services/dashboard/` |
| **Entry Point** | `uvicorn services.dashboard.app:app --host 0.0.0.0 --port 8080` |
| **Description** | Analyst Investigation Dashboard. FastAPI + HTMX + Jinja2 web UI providing investigation list, investigation detail, approvals queue, CTEM dashboard, CTI dashboard, Adversarial AI monitoring, SIEM connector management, settings, and a non-production test harness. Production RBAC uses Microsoft Entra access tokens; explicit role headers are limited to local development. |
| **Owner** | Platform Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | Analysts (browser) | HTTP/8080 |
| Infrastructure | PostgreSQL | TCP/5432 |
| Infrastructure | Redis | TCP/6379 |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirect to investigations |
| GET | `/investigations` | Investigation list page |
| GET | `/investigations/{id}` | Investigation detail page |
| GET | `/approvals` | Approvals queue page |
| POST | `/api/investigations/{id}/approve` | Approve investigation |
| POST | `/api/investigations/{id}/reject` | Reject investigation |
| GET | `/ctem` | CTEM exposure dashboard |
| GET | `/cti` | CTI threat intelligence dashboard |
| GET | `/adversarial-ai` | ATLAS monitoring dashboard |
| GET | `/connectors` | SIEM connector management |
| GET | `/settings` | System settings page |
| GET | `/test-harness` | Test data generation page |
| POST | `/api/test-harness/generate` | Generate test investigations |
| GET | `/metrics` | System metrics page |
| WS | `/ws/investigations` | Real-time investigation updates |
| GET | `/health` | Service health |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `REDIS_HOST` | No | Redis host for caching/sessions |
| `PORT` | No | Listen port (default: 8080) |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 2 | -- |

---

## 7. Audit Service

| Property | Value |
|----------|-------|
| **Package** | `services/audit_service/` |
| **Entry Point** | `python -m services.audit_service.service` |
| **Description** | Consumes audit events from Kafka, chains them using a per-tenant SHA-256 hash chain, persists to PostgreSQL `audit_records` table, and archives evidence packages to MinIO cold storage. Provides chain verification and evidence export. |
| **Owner** | Security Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Upstream | All services | Kafka (`audit.events`) |
| Infrastructure | PostgreSQL | TCP/5432 |
| Infrastructure | Kafka | TCP/9092 |
| Infrastructure | MinIO | TCP/9000 |

### Kafka Topics

| Topic | Direction | Schema |
|-------|-----------|--------|
| `audit.events` | Consumer | Audit event JSON (40 event types) |

### Database Tables

| Table | Access |
|-------|--------|
| `audit_records` | Read/Write |
| `audit_chain_state` | Read/Write |

### Key Components

| Module | Purpose |
|--------|---------|
| `chain.py` | SHA-256 hash chain computation, genesis records, chain verification |
| `evidence.py` | Evidence collection and packaging |
| `package_builder.py` | Audit evidence package assembly |
| `retention.py` | Cold storage lifecycle management |
| `verification.py` | Chain integrity verification |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka bootstrap address |
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `MINIO_ENDPOINT` | No | MinIO S3 endpoint |
| `MINIO_ACCESS_KEY` | No | MinIO access key |
| `MINIO_SECRET_KEY` | No | MinIO secret key |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 2 | -- |

---

## 8. Batch Scheduler

| Property | Value |
|----------|-------|
| **Package** | `batch_scheduler/` |
| **Entry Point** | `python -m batch_scheduler.scheduler` |
| **Description** | Schedules and processes offline LLM jobs using Tier 2 (Sonnet Batch) pricing. Tasks include FP pattern training, playbook generation, detection rule generation, retrospective analysis, agent red-teaming, and threat landscape summaries. Manages the embedding migration for Qdrant vector reindexing. |
| **Owner** | Platform Team |

### Dependencies

| Direction | Service | Protocol |
|-----------|---------|----------|
| Downstream | Context Gateway | HTTP/8030 |
| Infrastructure | PostgreSQL | TCP/5432 |
| Infrastructure | Kafka | TCP/9092 |
| Infrastructure | Qdrant | TCP/6333 |

### Kafka Topics

| Topic | Direction | Schema |
|-------|-----------|--------|
| `jobs.llm.priority.low` | Producer | Batch job payloads |
| `knowledge.playbook.updated` | Producer | Generated playbook notifications |
| `knowledge.fp.approved` | Producer | FP pattern training results |

### Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka bootstrap address |
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `QDRANT_HOST` | No | Qdrant host for embedding migration |
| `CONTEXT_GATEWAY_URL` | No | Context Gateway for batch LLM calls |

### Resource Requirements

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 1 | -- |

---

## 9. SIEM Adapters

### 9a. Sentinel Adapter

| Property | Value |
|----------|-------|
| **Package** | `sentinel_adapter/` |
| **Description** | Polls Microsoft Sentinel for alerts via the Azure Sentinel REST API, transforms them to raw alert format, and publishes to `alerts.raw`. Manages connector state and last-poll timestamps. |

### 9b. Elastic Adapter

| Property | Value |
|----------|-------|
| **Package** | `elastic_adapter/` |
| **Description** | Polls Elastic SIEM for alerts via the Elasticsearch API, transforms them to raw alert format, and publishes to `alerts.raw`. |

### 9c. Splunk Adapter

| Property | Value |
|----------|-------|
| **Package** | `splunk_adapter/` |
| **Description** | Polls Splunk Enterprise Security for notable events via the Splunk REST API, transforms them to raw alert format, and publishes to `alerts.raw`. |

### Common Adapter Properties

| Topic | Direction | Schema |
|-------|-----------|--------|
| `alerts.raw` | Producer | Raw SIEM alert JSON |

### Adapter Configuration

| Env Var | Required | Description |
|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka bootstrap address |
| `SENTINEL_WORKSPACE_ID` | Sentinel only | Azure Sentinel workspace ID |
| `SENTINEL_TENANT_ID` | Sentinel only | Azure AD tenant ID |
| `SENTINEL_CLIENT_ID` | Sentinel only | Azure AD app client ID |
| `SENTINEL_CLIENT_SECRET` | Sentinel only | Azure AD app client secret |
| `ELASTIC_HOST` | Elastic only | Elasticsearch host URL |
| `ELASTIC_API_KEY` | Elastic only | Elasticsearch API key |
| `SPLUNK_HOST` | Splunk only | Splunk management API host |
| `SPLUNK_TOKEN` | Splunk only | Splunk HEC/API token |

### Resource Requirements (per adapter)

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 250m | 500m |
| Memory | 256Mi | 512Mi |
| Replicas (prod) | 2 (Sentinel), 1 (Elastic), 1 (Splunk) |

---

## 10. Shared Libraries

| Package | Purpose |
|---------|---------|
| `shared/schemas/alert.py` | `CanonicalAlert` Pydantic model |
| `shared/schemas/investigation.py` | `GraphState`, `InvestigationState`, `DecisionEntry` |
| `shared/schemas/entity.py` | `NormalizedEntity`, `AlertEntities`, `EntityType` |
| `shared/schemas/risk.py` | `RiskState`, `RiskSignal`, risk classification |
| `shared/schemas/event_taxonomy.py` | `EventTaxonomy`, `EventCategory` (40 audit event types) |
| `shared/schemas/routing.py` | `TaskCapabilities`, `LLMProvider`, `ModelConfig` |
| `shared/schemas/scoring.py` | Investigation scoring models |
| `shared/schemas/audit.py` | Audit record schema |
| `shared/db/postgres.py` | Async PostgreSQL client |
| `shared/db/redis_cache.py` | Async Redis client |
| `shared/db/vector.py` | Qdrant vector client |
| `shared/db/neo4j_graph.py` | Neo4j graph client |
| `shared/db/embedding_migration.py` | Vector embedding migration utilities |
| `shared/auth/oidc.py` | OIDC/JWT token validation |
| `shared/auth/mtls.py` | mTLS certificate verification |
| `shared/auth/exceptions.py` | Authentication error types |
| `shared/adapters/ingest.py` | Base SIEM adapter interface |
| `shared/adapters/registry.py` | Adapter registration and discovery |
| `shared/audit/producer.py` | Kafka audit event producer |
| `shared/config/tenant_config.py` | Per-tenant configuration |
| `shared/config/zone_config.py` | Purdue zone configuration |
