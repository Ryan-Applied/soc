# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ALUSKORT** is an AI-powered Security Operations Center (SOC) platform. LLM-driven investigation graphs autonomously triage, enrich, and resolve security alerts via a microservices architecture built on Python 3.12, FastAPI, LangGraph, Anthropic Claude, Kafka, PostgreSQL 16, Redis 7, Qdrant, and Neo4j.

## Commands

### Local Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Start infrastructure only (Postgres, Redis, Kafka, Qdrant, Neo4j, MinIO)
docker-compose up -d postgres redis kafka qdrant neo4j minio

# Start all services (infra + application)
docker-compose --profile services up -d

# Start individual service
docker-compose up -d orchestrator context-gateway llm-router

# View logs
docker-compose logs -f orchestrator
```

### Running Services Directly

```bash
uvicorn services.dashboard.app:app --host 0.0.0.0 --port 8080      # Dashboard UI
uvicorn context_gateway.api:app --host 0.0.0.0 --port 8030         # Context Gateway
uvicorn llm_router.api:app --host 0.0.0.0 --port 8031              # LLM Router
python -m orchestrator.service                                        # Orchestrator (Kafka consumer)
python -m entity_parser.service                                       # Entity Parser (Kafka consumer)
python -m ctem_normaliser.service                                     # CTEM Normaliser
```

### Testing

```bash
# Full test suite with coverage (90% minimum enforced in CI)
pytest tests/ -v --cov=shared --cov-fail-under=90

# Specific module
pytest tests/test_context_gateway/ -v

# Single test
pytest tests/test_llm_router/test_router.py::test_route_ioc_extraction -v
```

### Infrastructure Setup

```bash
# Initialize Kafka topics, Neo4j schema, Qdrant collections after infra starts
python infra/scripts/create_kafka_topics.py
python infra/scripts/init_neo4j.py
python infra/scripts/init_qdrant.py
```

PostgreSQL migrations run automatically on container start from `infra/migrations/`.

## Architecture

### Alert Investigation Pipeline

```
SIEM (Elastic/Sentinel/Splunk) → Adapter → alerts.raw (Kafka)
                                               ↓
                                        Entity Parser (entity_parser/)
                                               ↓
                                       alerts.normalized (Kafka)
                                               ↓
                                  Orchestrator — LangGraph graph (orchestrator/)
                                    ├→ IOC Extractor
                                    ├→ FP Short-Circuit (Redis ~1ms)
                                    ├→ Parallel Enrichment:
                                    │   ├→ Context Enricher (Redis + Postgres UEBA)
                                    │   ├→ CTEM Correlator (Postgres)
                                    │   └→ ATLAS Mapper (MITRE ATLAS)
                                    ├→ Reasoning Agent (Claude Sonnet via Context Gateway)
                                    └→ Response Agent (with human approval gate)
                                               ↓
                                    investigations.completed (Kafka)
                                               ↓
                                    PostgreSQL + Dashboard (services/dashboard/)
```

### Key Modules

| Module | Role |
|--------|------|
| `orchestrator/graph.py` | LangGraph state machine — the core investigation engine |
| `orchestrator/agents/` | Individual agents: ioc_extractor, enricher, ctem, atlas, reasoning, response |
| `context_gateway/` | LLM request pipeline: sanitize → PII redact → call → validate → deanonymize |
| `llm_router/router.py` | Routes tasks to LLM tiers; health-aware fallback; cost tracking |
| `entity_parser/service.py` | Kafka consumer extracting IPs, domains, hashes, processes from raw alerts |
| `services/dashboard/app.py` | 20-page FastAPI + HTMX analyst UI (port 8080) |
| `shared/schemas/` | Pydantic data contracts shared across all services |
| `shared/db/` | Async database clients (PostgreSQL/asyncpg, Redis, Qdrant, Neo4j) |
| `shared/audit/` | Kafka producer for ISO 27001 chain-verified audit events |
| `batch_scheduler/` | Cron jobs for FP pattern training and embedding generation |
| `atlas_detection/` | MITRE ATLAS adversarial AI threat detection |
| `ctem_normaliser/` | Normalizes CTEM exposures from Wiz, Snyk, ART, Garak |

### LLM Tier Routing (`llm_router/router.py`)

- **Tier 0 — Haiku:** `ioc_extraction`, `log_summarisation`, `severity_assessment` (fast, cheap)
- **Tier 1 — Sonnet:** `investigation`, `ctem_correlation`, `atlas_reasoning` (deep reasoning)
- **Tier 2 — Sonnet Batch:** `fp_pattern_training`, `playbook_generation` (offline)
- Hard cost cap: $1,000/month; soft alert: $500/month (enforced in `context_gateway/spend_guard.py`)

### Investigation Graph States

`RECEIVED → PARSING → ENRICHING → REASONING → RESPONDING → AWAITING_HUMAN → CLOSED / FAILED`

Parallel enrichment (context, CTEM, ATLAS) runs via `asyncio.gather()`. FP short-circuit hits Redis before any LLM calls.

### Context Gateway Pipeline (`context_gateway/`)

All LLM calls flow through this pipeline: `gateway.py` orchestrates `injection_detector.py` → `pii_redactor.py` → `anthropic_client.py` → `output_validator.py` → deanonymize. Prompt injection and PII redaction protect both security and privacy.

### Shared Infrastructure

- **Kafka topics:** All inter-service communication (`alerts.raw`, `alerts.normalized`, `investigations.completed`, `ctem.normalized`, plus audit topics)
- **PostgreSQL:** 13 migrations covering investigations, CTEM, ATLAS, audit, FP governance, LLM provider registry
- **Redis:** IOC caching, FP pattern lookups, session data
- **Qdrant:** Vector embeddings for MITRE ATT&CK, playbooks, past incidents
- **Neo4j:** Attack path graphs and entity relationships
- **MinIO/S3:** Evidence logs, raw alert payloads with lifecycle policies

### Dashboard (`services/dashboard/`)

FastAPI + Jinja2 + HTMX + Tailwind CSS + Chart.js. 20 pages organized as: core analyst pages (investigations, approvals, metrics), threat intel pages (CTEM, CTI, adversarial AI, FP patterns), and platform admin pages (LLM health, connectors, audit trail, settings). WebSocket endpoint for real-time investigation updates. `RBACMiddleware` enforces JWT-based authorization.

### Service Container Model

All services share a single `Dockerfile` (Python 3.12-slim + librdkafka-dev for confluent-kafka). Per-service entry points are defined in `docker-compose.yml`. Each service exposes a `/health` HTTP endpoint.

## Required Environment Variables

```bash
POSTGRES_DSN=postgresql://aluskort:localdev@localhost:5432/aluskort
REDIS_HOST=localhost
REDIS_PORT=6379
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
QDRANT_HOST=localhost
NEO4J_URI=bolt://localhost:7687
NEO4J_AUTH=neo4j/localdev
ANTHROPIC_API_KEY=sk-ant-...   # Required for any LLM calls
```

## Production Deployment

Full AWS deployment via Terraform: `infra/terraform/deploy.sh` (interactive wizard). Targets ECS Fargate + RDS PostgreSQL + ElastiCache + MSK (managed Kafka) + ALB. K8s manifests also available at `infra/k8s/`.
