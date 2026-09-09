# Testing Guide

## Test Architecture

ALUSKORT maintains a comprehensive test suite covering unit tests, integration tests, and security tests across all services.

### Test Directory Structure

```
tests/
  +-- atlas_detection/        # ATLAS detection rule tests
  +-- batch_scheduler/        # Batch scheduler and FP generator tests
  +-- context_gateway/        # Context Gateway pipeline tests
  +-- ctem_normaliser/        # CTEM normaliser tests (all source tools)
  +-- elastic_adapter/        # Elastic SIEM adapter tests
  +-- entity_parser/          # Entity parsing and validation tests
  +-- infra/                  # Infrastructure script tests
  +-- llm_router/             # LLM router and circuit breaker tests
  +-- ops/                    # Operations (health, metrics, alerts) tests
  +-- orchestrator/           # Orchestrator, state machine, agent tests
  +-- sentinel_adapter/       # Sentinel SIEM adapter tests
  +-- services/
  |     +-- audit_service/    # Audit chain, evidence, retention tests
  |     +-- dashboard/        # Dashboard route and middleware tests
  +-- shared/                 # Shared library tests (schemas, auth, DB)
  +-- splunk_adapter/         # Splunk SIEM adapter tests
```

---

## Running Tests

### Full Test Suite

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=. --cov-report=html

# Run with parallel execution
pytest -n auto
```

### By Module

```bash
# Entity Parser tests
pytest tests/entity_parser/

# Orchestrator tests
pytest tests/orchestrator/

# Context Gateway tests
pytest tests/context_gateway/

# LLM Router tests
pytest tests/llm_router/

# ATLAS Detection tests
pytest tests/atlas_detection/

# CTEM Normaliser tests
pytest tests/ctem_normaliser/

# Dashboard tests
pytest tests/services/dashboard/

# Audit Service tests
pytest tests/services/audit_service/

# Shared library tests
pytest tests/shared/
```

### By Marker

```bash
# Run only unit tests (no external dependencies)
pytest -m unit

# Run integration tests
pytest -m integration

# Run security-specific tests
pytest -m security
```

### Specific Test Files

```bash
# Run a single test file
pytest tests/orchestrator/test_graph.py

# Run a specific test function
pytest tests/orchestrator/test_graph.py::test_full_pipeline

# Run tests matching a keyword
pytest -k "fp_shortcircuit"
```

---

## Test Harness

The test harness (`services/dashboard/routes/test_harness.py`) generates synthetic investigations for end-to-end testing and demonstration.

### Scenarios

The harness provides 15 pre-built scenarios across 5 categories:

#### APT / Nation-State (3 scenarios)

| # | Title | Severity | Techniques |
|---|-------|----------|------------|
| 1 | Cobalt Strike Beacon -- C2 Callback Detected | Critical | T1071.001, T1218.011 |
| 2 | Suspected APT Lateral Movement via PsExec | High | T1021.002, T1570 |
| 3 | DLL Side-Loading from Suspicious Path | High | T1574.002, T1059.001 |

#### Ransomware (3 scenarios)

| # | Title | Severity | Techniques |
|---|-------|----------|------------|
| 4 | Ransomware Pre-Encryption: Volume Shadow Copy Deletion | Critical | T1490, T1059.001 |
| 5 | Mass File Encryption Detected on File Server | Critical | T1486, T1083 |
| 6 | Ransomware C2 Beacon to Known Infrastructure | High | T1071.001, T1573 |

#### Insider Threat (3 scenarios)

| # | Title | Severity | Techniques |
|---|-------|----------|------------|
| 7 | Unusual Data Transfer to Personal Cloud Storage | High | T1567.002, T1074 |
| 8 | Privileged Account Accessing Sensitive Repositories | Medium | T1213, T1078.002 |
| 9 | Bulk Download of Customer Database Records | High | T1530, T1078 |

#### Cloud Compromise (3 scenarios)

| # | Title | Severity | Techniques |
|---|-------|----------|------------|
| 10 | AWS Root Account API Key Used from Unknown IP | Critical | T1078.004, T1098 |
| 11 | Azure AD Conditional Access Policy Disabled | High | T1562.001, T1098.001 |
| 12 | GCP Service Account Key Exported | Medium | T1552.001, T1078.004 |

#### Adversarial AI (3 scenarios)

| # | Title | Severity | ATLAS Techniques |
|---|-------|----------|-----------------|
| 13 | ML Model Training Data Poisoning Attempt | High | AML.T0020 |
| 14 | LLM Prompt Injection via Customer Support Channel | High | AML.T0051 |
| 15 | Edge Node Inference Model Tampering | Critical | AML.T0040 |

### Using the Test Harness

#### Via Dashboard UI

1. Navigate to `http://localhost:8080/test-harness`
2. Select scenario category or individual scenarios
3. Click "Generate" to create investigations
4. Investigations appear immediately in the investigation list

#### Via API

```bash
# Generate a single scenario
curl -X POST http://localhost:8080/api/test-harness/generate \
  -H "Content-Type: application/json" \
  -d '{"scenario_tags": ["apt"], "count": 1}'

# Generate all scenarios
curl -X POST http://localhost:8080/api/test-harness/generate-all

# Clear test data
curl -X DELETE http://localhost:8080/api/test-harness/clear
```

### What Gets Generated

Each test scenario creates a complete `GraphState` with:

- Full alert metadata (title, description, severity, tactics, techniques)
- Parsed entities (accounts, hosts, IPs, files, processes)
- IOC matches with threat intelligence data
- CTEM exposure correlations with consequence-weighted scoring
- ATLAS technique mappings (for adversarial AI scenarios)
- Decision chain with timestamped entries from each agent
- Recommended response actions
- UEBA context with risk states
- Similar incidents from synthetic history
- Playbook matches
- Scoring breakdown (confidence, LLM calls, cost)

---

## Integration Test Setup

### Prerequisites

Integration tests require infrastructure services to be running:

```bash
# Start infrastructure
docker compose up -d

# Create Kafka topics
python -m infra.scripts.create_kafka_topics

# Initialise Qdrant
python -m infra.scripts.init_qdrant

# Initialise Neo4j
python -m infra.scripts.init_neo4j
```

### Environment Variables

```bash
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
export POSTGRES_DSN=postgresql://aluskort:localdev@localhost:5432/aluskort
export REDIS_HOST=localhost
export QDRANT_HOST=localhost
export NEO4J_URI=bolt://localhost:7687
```

### Running Integration Tests

```bash
# Run all integration tests
pytest -m integration

# Run with infrastructure connectivity checks
pytest tests/infra/
```

---

## Performance Test Baselines

### Investigation Pipeline Latency

| Stage | Target | Measurement |
|-------|--------|-------------|
| Entity Parsing | < 100ms | From `alerts.raw` consumption to `alerts.normalized` production |
| FP Short-Circuit | < 50ms | FP pattern check and auto-close |
| Parallel Enrichment | < 5s | Context Enricher + CTEM Correlator + ATLAS Mapper (parallel) |
| Reasoning (Tier 0) | < 3s | Haiku-tier classification |
| Reasoning (Tier 1) | < 15s | Sonnet-tier deep analysis |
| Reasoning (Tier 1+) | < 45s | Opus-tier complex analysis |
| Full Pipeline (FP) | < 200ms | Alert to auto-close for known FP |
| Full Pipeline (TP) | < 30s | Alert to classification for true positive |

### Throughput Targets

| Metric | Target |
|--------|--------|
| Alerts ingested | 100/minute sustained |
| Investigations completed | 50/minute |
| FP auto-close | 80/minute |
| Kafka message processing | < 100ms p99 |
| Dashboard page load | < 500ms |
| WebSocket update latency | < 200ms |

### Resource Baselines

| Service | Idle CPU | Idle Memory | Load CPU | Load Memory |
|---------|---------|-------------|---------|-------------|
| Entity Parser | < 5% | ~128MB | < 30% | ~256MB |
| Orchestrator | < 10% | ~256MB | < 60% | ~512MB |
| Context Gateway | < 5% | ~256MB | < 40% | ~512MB |
| LLM Router | < 2% | ~128MB | < 20% | ~256MB |
| Dashboard | < 5% | ~128MB | < 30% | ~256MB |

---

## Security Test Procedures

### Prompt Injection Testing

Test the Context Gateway's injection detection and response:

```bash
# Run injection detection tests
pytest tests/context_gateway/test_injection_detector.py
pytest tests/context_gateway/test_injection_classifier.py

# Test the full gateway pipeline with injection payloads
pytest tests/context_gateway/test_gateway.py -k "injection"
```

Test scenarios include:
- Direct injection ("Ignore all previous instructions...")
- Indirect injection (embedded in alert descriptions)
- Encoded injection (base64, URL encoding, Unicode)
- Multi-stage injection (spread across multiple fields)

### Output Validation Testing

Test the deny-by-default output validator:

```bash
pytest tests/context_gateway/test_output_validator.py
```

Validates:
- Known technique IDs pass through
- Unknown/hallucinated technique IDs are quarantined
- Quarantined IDs are stripped from output
- Audit events are emitted for quarantined IDs

### PII Redaction Testing

```bash
pytest tests/context_gateway/test_pii_redactor.py
```

Validates:
- All PII types are detected and replaced
- Redaction map enables correct deanonymisation
- No PII leaks into LLM API calls
- Edge cases (multiple PII in one string, nested PII)

### RBAC Testing

```bash
pytest tests/services/dashboard/test_auth.py
```

Validates:
- Microsoft Entra token validation and application-role mapping
- Explicit local-development role-header authentication
- Role hierarchy enforcement (admin > senior_analyst > analyst)
- Protected route access control
- Invalid role rejection

### Audit Chain Integrity Testing

```bash
pytest tests/services/audit_service/test_chain.py
```

Validates:
- Genesis record creation
- Hash chain continuity
- Chain verification detects tampering
- Per-tenant isolation
- Concurrent write safety

### Kill Switch Testing

```bash
pytest tests/orchestrator/test_kill_switch.py
```

Validates:
- Kill switch activation/deactivation across all 4 dimensions
- FP auto-close blocked when any kill switch is active
- Fail-open behaviour when Redis is unavailable
- Audit event emission

### ATLAS Detection Rule Testing

```bash
pytest tests/atlas_detection/
```

Each detection rule has tests for:
- Trigger conditions (true positive)
- Non-trigger conditions (true negative)
- Confidence calculation accuracy
- Edge cases (zero baseline, missing data)
- Trust downgrade and confidence floor application

---

## Test Configuration

### pytest.ini / pyproject.toml

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "unit: Unit tests (no external dependencies)",
    "integration: Integration tests (require infrastructure)",
    "security: Security-specific tests",
]
asyncio_mode = "auto"
```

### Fixtures

Common test fixtures are provided in `conftest.py` files:

| Fixture | Scope | Purpose |
|---------|-------|---------|
| `mock_db` | function | Mock PostgreSQL client |
| `mock_redis` | function | Mock Redis client |
| `mock_kafka` | function | Mock Kafka producer/consumer |
| `sample_alert` | function | Pre-built `CanonicalAlert` |
| `sample_graph_state` | function | Pre-built `GraphState` |
| `mock_anthropic` | function | Mock Anthropic API client |
| `mock_audit_producer` | function | Mock audit event producer |
