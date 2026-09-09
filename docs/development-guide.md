# ALUSKORT — Development Guide

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Generated:** 2026-02-21

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | >=3.12 | Runtime |
| pip | Latest | Package management |
| Docker | Latest | Container runtime |
| Docker Compose | v3.9+ | Local infrastructure |
| Git | Any | Source control |

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd SOC

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

This installs:
- **Runtime deps:** pydantic, asyncpg, redis, qdrant-client, neo4j, PyJWT, confluent-kafka, pyyaml, anthropic
- **Dev deps:** pytest, pytest-asyncio, cryptography

## Local Infrastructure

Start all 6 infrastructure services:

```bash
docker-compose up -d
```

| Service | Port | Credentials | Health Check |
|---------|------|-------------|-------------|
| PostgreSQL 16 | 5432 | `aluskort:localdev` / db: `aluskort` | `pg_isready -U aluskort` |
| Redis 7 | 6379 | No password | `redis-cli ping` |
| Qdrant | 6333 (HTTP), 6334 (gRPC) | None | `curl localhost:6333/healthz` |
| Neo4j 5 | 7474 (HTTP), 7687 (Bolt) | `neo4j:localdev` | Cypher shell |
| Kafka (Redpanda) | 9092 | None | `rpk cluster health` |
| MinIO | 9000 (API), 9001 (Console) | `minioadmin:minioadmin` | — |

SQL migrations run automatically via the Postgres `docker-entrypoint-initdb.d` volume mount.

## Database Initialization

After infrastructure is healthy, initialize the non-SQL stores:

```bash
# Create 31 Kafka topics with partition/retention config
python infra/scripts/create_kafka_topics.py

# Create Neo4j constraints, indexes, and sample data
python infra/scripts/init_neo4j.py

# Create 4 Qdrant vector collections (HNSW m=16, ef=200)
python infra/scripts/init_qdrant.py
```

## Environment Variables

| Variable | Default (dev) | Required |
|----------|--------------|----------|
| `POSTGRES_DSN` | `postgresql://aluskort:localdev@localhost:5432/aluskort` | For DB tests |
| `REDIS_HOST` | `localhost` | For cache tests |
| `REDIS_PORT` | `6379` | For cache tests |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | For Kafka services |
| `QDRANT_HOST` | `localhost` | For vector tests |
| `NEO4J_URI` | `bolt://localhost:7687` | For graph tests |
| `NEO4J_AUTH` | `neo4j/localdev` | For graph tests |
| `ANTHROPIC_API_KEY` | — | **Required** for LLM calls |
| `MONTHLY_SPEND_HARD_CAP` | `1000` | Cost control |
| `MONTHLY_SPEND_SOFT_ALERT` | `500` | Cost control |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Vector embeddings |
| `EMBEDDING_DIMENSIONS` | `1536` | Vector dimensions |

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v --tb=short

# Run with coverage (CI mode)
python -m pytest tests/ --cov=shared --cov-report=xml --cov-fail-under=90 -v --tb=short

# Run specific test module
python -m pytest tests/test_context_gateway/ -v

# Run a single test
python -m pytest tests/test_llm_router/test_router.py::test_route_ioc_extraction -v
```

**CI requires:** PostgreSQL + Redis running (provided as GitHub Actions service containers).

**Coverage gate:** 90% on `shared/` package.

### Test Structure

| Directory | Tests | Covers |
|-----------|-------|--------|
| `tests/test_schemas/` | 8 | Pydantic models, enums, validation |
| `tests/test_db/` | 4 | PG, Redis, Qdrant, Neo4j clients |
| `tests/test_auth/` | 3 | OIDC, mTLS, error codes |
| `tests/test_context_gateway/` | 14 | Injection, PII, prompts, spend, integration |
| `tests/test_llm_router/` | 6 | Routing, circuit breaker, escalation |
| `tests/test_orchestrator/` | 12 | Graph, agents, FP, constraints, integration |
| `tests/test_entity_parser/` | 5 | Parsing, validation, injection |
| `tests/test_ctem_normaliser/` | 7 | Normalisers, models, upsert |
| `tests/test_atlas_detection/` | 3 | Rules, models, runner |
| `tests/test_batch_scheduler/` | 5 | Scheduler, client, processor, FP gen |
| `tests/test_sentinel_adapter/` | 3 | Adapter, connector, contract |
| `tests/test_ops/` | 3 | Alerts, health, metrics |
| `tests/test_infra/` | 6 | DDL, Kafka, Neo4j, Qdrant, Docker |
| `tests/test_audit/` | 7 | Chain, evidence, verification, producer |
| `tests/security/` | 1 | Red-team injection regression |

## CI/CD Pipeline

**GitHub Actions** (`.github/workflows/ci-cd.yml`):

### CI (on push/PR to `master`)
1. Spin up PostgreSQL 16 + Redis 7 service containers
2. Install Python 3.12 + `pip install -e ".[dev]" pytest-cov`
3. Run `pytest tests/ --cov=shared --cov-fail-under=90`
4. Upload coverage artifact

### CD (on push to `master` only, after CI passes)
1. Matrix build: 8 services in parallel
2. Build from `./Dockerfile` with `SERVICE` build arg
3. Push to GHCR: `ghcr.io/<owner>/aluskort/<service>:<sha>` + `:latest`

**Services built:** entity-parser, ctem-normaliser, orchestrator, context-gateway, llm-router, batch-scheduler, sentinel-adapter, atlas-detection

## Project Packages

Defined in `pyproject.toml` `[tool.setuptools.packages.find]`:

```
shared*, infra*, entity_parser*, sentinel_adapter*, context_gateway*,
llm_router*, orchestrator*, ctem_normaliser*, atlas_detection*,
batch_scheduler*, ops*
```

## Common Development Tasks

### Adding a new Pydantic schema
1. Create/edit file in `shared/schemas/`
2. Export from `shared/schemas/__init__.py`
3. Add tests in `tests/test_schemas/`

### Adding a new detection rule
1. Implement `DetectionRule` subclass in `atlas_detection/rules.py`
2. Register in `DetectionRunner` rule list
3. Add tests in `tests/test_atlas_detection/test_rules.py`

### Adding a new CTEM normaliser
1. Subclass `BaseNormaliser` in `ctem_normaliser/`
2. Register topic mapping in `CTEMNormaliserService.get_normaliser()`
3. Add Kafka topic in `infra/scripts/create_kafka_topics.py`
4. Add tests in `tests/test_ctem_normaliser/`

### Adding a new orchestrator agent
1. Implement `AgentNode` protocol in `orchestrator/agents/`
2. Wire into `InvestigationGraph` in `orchestrator/graph.py`
3. Add agent role to `shared/schemas/investigation.py` `AgentRole` enum
4. Update `ROLE_PERMISSIONS` in `orchestrator/executor_constraints.py`
5. Add tests in `tests/test_orchestrator/`
