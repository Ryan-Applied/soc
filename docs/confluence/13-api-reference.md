# API Reference

## Dashboard API

**Base URL**: `http://localhost:8080`

### Pages (HTML)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| GET | `/` | Redirect to `/investigations` | No |
| GET | `/investigations` | Investigation list page | Yes |
| GET | `/investigations/{id}` | Investigation detail page | Yes |
| GET | `/investigations/{id}/timeline` | Investigation timeline | Yes |
| GET | `/approvals` | Approvals queue page | Yes |
| GET | `/ctem` | CTEM exposure dashboard | Yes |
| GET | `/cti` | CTI threat intelligence dashboard | Yes |
| GET | `/adversarial-ai` | ATLAS monitoring dashboard | Yes |
| GET | `/connectors` | SIEM connector management | Yes (admin) |
| GET | `/settings` | System settings page | Yes (admin) |
| GET | `/metrics` | System metrics page | Yes |
| GET | `/test-harness` | Test data generation page | Yes |

### REST API Endpoints

#### Investigations

| Method | Path | Description | Request Body | Response |
|--------|------|-------------|-------------|----------|
| GET | `/api/investigations` | List all investigations | -- | `[{investigation_id, state, alert_id, severity, classification, confidence, created_at}]` |
| GET | `/api/investigations/{id}` | Get investigation detail | -- | Full `GraphState` JSON |
| POST | `/api/investigations/{id}/approve` | Approve investigation | -- | `{status: "approved"}` |
| POST | `/api/investigations/{id}/reject` | Reject investigation | -- | `{status: "rejected"}` |

**Approve/Reject requires**: `senior_analyst` or `admin` role

#### Test Harness

| Method | Path | Description | Request Body | Response |
|--------|------|-------------|-------------|----------|
| GET | `/api/test-harness/scenarios` | List available scenarios | -- | `[{tag, title, severity, category}]` |
| POST | `/api/test-harness/generate` | Generate test investigations | `{scenario_tags: ["apt", "ransomware"], count: 1}` | `{generated: [{investigation_id, title}]}` |
| POST | `/api/test-harness/generate-all` | Generate all 15 scenarios | -- | `{generated: [...]}` |
| DELETE | `/api/test-harness/clear` | Clear test data | -- | `{deleted: count}` |

#### Connectors

| Method | Path | Description | Request Body | Response |
|--------|------|-------------|-------------|----------|
| GET | `/api/connectors` | List connectors | -- | `[{connector_id, type, status, last_poll_at}]` |
| POST | `/api/connectors` | Create connector | `{type, config}` | `{connector_id}` |
| PUT | `/api/connectors/{id}` | Update connector | `{config, status}` | `{connector_id}` |
| DELETE | `/api/connectors/{id}` | Delete connector | -- | `{deleted: true}` |
| POST | `/api/connectors/{id}/test` | Test connectivity | -- | `{success, message}` |

#### Settings

| Method | Path | Description | Request Body | Response |
|--------|------|-------------|-------------|----------|
| GET | `/api/settings` | Get system settings | -- | `{log_level, spend_limits, kill_switches}` |
| PUT | `/api/settings` | Update settings | `{key, value}` | `{updated: true}` |
| GET | `/api/settings/spend` | Get spend summary | -- | `{monthly_total, by_tier, by_tenant}` |

#### Metrics

| Method | Path | Description | Response |
|--------|------|-------------|----------|
| GET | `/api/metrics/investigations` | Investigation counts by state | `{received: n, parsing: n, ...}` |
| GET | `/api/metrics/fp-rate` | FP auto-close rate | `{rate: 0.98, total: n, auto_closed: n}` |
| GET | `/api/metrics/cost` | LLM cost summary | `{monthly_total, daily_avg, by_tier}` |

### Health

| Method | Path | Description | Response |
|--------|------|-------------|----------|
| GET | `/health` | Service health check | `{"status": "ok", "service": "dashboard"}` |

### WebSocket

| Path | Description | Protocol |
|------|-------------|----------|
| `ws://localhost:8080/ws/investigations` | Real-time investigation updates | WebSocket |

**Message Format** (server -> client):

```json
{
  "type": "investigation_update",
  "data": {
    "investigation_id": "abc-123",
    "state": "enriching",
    "severity": "critical",
    "classification": "APT lateral movement"
  }
}
```

---

## Context Gateway API

**Base URL**: `http://localhost:8030`

### Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/v1/complete` | Submit LLM completion request | mTLS |
| GET | `/v1/spend` | Query current spend metrics | mTLS |
| GET | `/health` | Service health | None |

### POST `/v1/complete`

**Request Body**:

```json
{
  "agent_id": "reasoning_agent",
  "task_type": "investigation",
  "system_prompt": "You are a SOC analyst...",
  "user_content": "Alert data: ...",
  "output_schema": {"type": "object", "properties": {...}},
  "tenant_id": "default"
}
```

**Response Body**:

```json
{
  "content": "Analysis result...",
  "model_id": "claude-sonnet-4-5-20250929",
  "tokens_used": 1523,
  "valid": true,
  "raw_output": "Original LLM output before stripping...",
  "validation_errors": [],
  "quarantined_ids": [],
  "metrics": {
    "model_id": "claude-sonnet-4-5-20250929",
    "input_tokens": 1200,
    "output_tokens": 323,
    "cost_usd": 0.0084,
    "latency_ms": 2150
  },
  "injection_detections": []
}
```

**Error Responses**:

| Status | Condition | Body |
|--------|-----------|------|
| 402 | Monthly spend hard cap reached | `{"detail": "Monthly spend cap exceeded"}` |
| 422 | Invalid request body | `{"detail": "Validation error..."}` |
| 503 | LLM provider unavailable | `{"detail": "All providers unavailable"}` |

### GET `/v1/spend`

**Response Body**:

```json
{
  "monthly_total_usd": 342.50,
  "soft_limit_usd": 500,
  "hard_cap_usd": 1000,
  "by_model": {
    "claude-haiku-4-5-20251001": 45.20,
    "claude-sonnet-4-5-20250929": 285.30,
    "claude-opus-4-6": 12.00
  },
  "by_tenant": {
    "default": 342.50
  }
}
```

---

## LLM Router API

**Base URL**: `http://localhost:8031`

### Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/v1/route` | Route a task to optimal model tier | mTLS |
| GET | `/v1/models` | List available models and tiers | mTLS |
| GET | `/v1/health-status` | Provider health and degradation level | mTLS |
| GET | `/health` | Service health | None |

### POST `/v1/route`

**Request Body**:

```json
{
  "task_type": "investigation",
  "context_tokens": 50000,
  "time_budget_seconds": 30,
  "alert_severity": "critical",
  "tenant_tier": "standard",
  "requires_reasoning": true,
  "previous_confidence": null
}
```

**Response Body**:

```json
{
  "tier": "tier_1",
  "model_config": {
    "provider": "anthropic",
    "model_id": "claude-sonnet-4-5-20250929",
    "max_context_tokens": 200000,
    "cost_per_mtok_input": 3.0,
    "cost_per_mtok_output": 15.0
  },
  "max_tokens": 8192,
  "temperature": 0.2,
  "use_extended_thinking": false,
  "use_prompt_caching": true,
  "reason": "base=tier_1; critical+reasoning->min_tier_1",
  "fallback_configs": [...],
  "degradation_level": "full_capability"
}
```

### GET `/v1/health-status`

**Response Body**:

```json
{
  "degradation_level": "full_capability",
  "providers": {
    "anthropic": {"status": "healthy", "error_rate": 0.001},
    "openai": {"status": "healthy", "error_rate": 0.0}
  },
  "circuit_breaker": "closed"
}
```

---

## Kafka Topic Contracts

### Producer Schemas

#### `alerts.raw`

Published by SIEM adapters. Schema varies by source but must include:

```json
{
  "source": "sentinel|elastic|splunk",
  "alert_id": "string",
  "timestamp": "ISO 8601",
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low|informational",
  "raw_payload": {}
}
```

#### `alerts.normalized`

Published by Entity Parser. Schema: `CanonicalAlert`

```json
{
  "alert_id": "string",
  "source": "string",
  "timestamp": "ISO 8601",
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low|informational",
  "tactics": ["string"],
  "techniques": ["string"],
  "entities_raw": "string",
  "product": "string",
  "tenant_id": "string",
  "raw_payload": {}
}
```

#### `audit.events`

Published by all services. Standardised audit event format:

```json
{
  "audit_id": "UUID",
  "tenant_id": "string",
  "timestamp": "ISO 8601",
  "event_type": "EventTaxonomy value (40 types)",
  "event_category": "decision|action|approval|security|system",
  "severity": "info|warning|error|critical",
  "actor_type": "agent|human|system",
  "actor_id": "string",
  "investigation_id": "string (optional)",
  "alert_id": "string (optional)",
  "context": {},
  "record_version": "1.0",
  "source_service": "string"
}
```

#### `ctem.normalized`

Published by CTEM Normaliser. Schema: `CTEMExposure`

```json
{
  "exposure_key": "string (sha256[:16])",
  "ts": "ISO 8601",
  "source_tool": "wiz|snyk|garak|art",
  "title": "string",
  "description": "string",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "original_severity": "string",
  "asset_id": "string",
  "asset_type": "string",
  "asset_zone": "string (Purdue zone)",
  "exploitability_score": 0.0-1.0,
  "physical_consequence": "safety_life|equipment|downtime|data_loss",
  "ctem_score": 0.0-10.0,
  "sla_deadline": "ISO 8601",
  "tenant_id": "string"
}
```

---

## Authentication Headers

### Dashboard (Local Development Only)

| Header | Value | Description |
|--------|-------|-------------|
| `X-User-Role` | `analyst`, `senior_analyst`, `admin` | User role for RBAC |

Header authentication must be explicitly selected for local development, and a
valid role is required. Production requires a Microsoft Entra bearer token and
rejects missing tokens; it never defaults to `admin`.

### Inter-Service (Production)

| Method | Description |
|--------|-------------|
| mTLS | Mutual TLS with client certificates signed by internal CA |
| Bearer Token | OIDC JWT token in `Authorization: Bearer <token>` header |

---

## Error Response Format

All API errors follow a consistent format:

```json
{
  "detail": "Human-readable error message"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 302 | Redirect (e.g., root to `/investigations`) |
| 400 | Bad request (invalid parameters) |
| 401 | Unauthorized (missing or invalid role) |
| 402 | Payment required (spend cap exceeded) |
| 403 | Forbidden (insufficient role for operation) |
| 404 | Not found (investigation ID not found) |
| 422 | Validation error (invalid request body) |
| 500 | Internal server error |
| 503 | Service unavailable (dependency down) |

---

## Rate Limiting

### Current Implementation

Rate limiting is not enforced in the MVP. Production deployment should add:

| Endpoint | Rate Limit | Window |
|----------|-----------|--------|
| `/v1/complete` (Context Gateway) | 100 requests | per minute |
| `/api/test-harness/generate` | 10 requests | per minute |
| WebSocket connections | 50 concurrent | per IP |

### Recommended Implementation

Use Redis-backed rate limiting via the `shared/db/redis_cache.py` client:
- Token bucket algorithm per API key/role
- Separate limits for read vs. write operations
- Return `429 Too Many Requests` with `Retry-After` header
