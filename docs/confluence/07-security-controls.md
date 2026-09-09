# Security Controls

## Authentication

### External Authentication (OIDC)

ALUSKORT supports OpenID Connect (OIDC) for external user authentication via the `OIDCValidator` class (`shared/auth/oidc.py`).

| Property | Value |
|----------|-------|
| **Protocol** | OIDC / JWT (RS256) |
| **JWKS Endpoint** | Configurable via `jwks_url` |
| **Audience Validation** | Optional, configurable |
| **Issuer Validation** | Optional, configurable |
| **JWKS Cache TTL** | 3600 seconds (1 hour) |
| **Token Refresh** | Automatic JWKS refetch on `kid` cache miss |

Error codes for authentication failures:

| Code | Meaning |
|------|---------|
| `TOKEN_MALFORMED` | JWT cannot be decoded |
| `TOKEN_EXPIRED` | Token `exp` claim is in the past |
| `TOKEN_INVALID_SIGNATURE` | Signature verification failed |
| `TOKEN_INVALID_AUDIENCE` | `aud` claim mismatch |
| `TOKEN_INVALID_ISSUER` | `iss` claim mismatch |
| `JWKS_FETCH_FAILED` | Cannot reach JWKS endpoint |

### Inter-Service Authentication (mTLS)

Service-to-service communication uses mutual TLS (`shared/auth/mtls.py`):
- Each service has a client certificate signed by the internal CA
- The receiving service validates the client certificate chain
- Used between Orchestrator, Context Gateway, LLM Router, and Audit Service

### Dashboard Authentication

Production uses single-tenant Microsoft Entra access-token validation. Tokens
must have the configured audience, tenant, issuer, user object ID, and an
ALUSKORT application role. Missing or invalid tokens are rejected; there is no
default administrator. Explicit `X-User-Role`/`X-User-Id` headers are supported
only in local-development mode. Public paths exempt from authentication are
`/health`, `/docs`, `/openapi.json`, and `/redoc`. The test harness is disabled
in production and requires an explicit feature flag in development.

---

## Role-Based Access Control (RBAC)

### Role Hierarchy

```
admin
  |-- senior_analyst
        |-- analyst
```

Higher roles inherit all permissions of lower roles.

### Role Definitions

| Role | Description | Capabilities |
|------|-------------|-------------|
| `analyst` | SOC Analyst (Tier 1) | View investigations, view dashboards, view CTEM/CTI data |
| `senior_analyst` | Senior SOC Analyst (Tier 2) | All analyst permissions + approve/reject investigations, manage FP patterns |
| `admin` | SOC Manager / Platform Admin | All permissions + kill switch activation, system settings, connector management |

### Permissions Matrix

| Action | analyst | senior_analyst | admin |
|--------|---------|---------------|-------|
| View investigations list | Yes | Yes | Yes |
| View investigation detail | Yes | Yes | Yes |
| View CTEM dashboard | Yes | Yes | Yes |
| View CTI dashboard | Yes | Yes | Yes |
| View Adversarial AI dashboard | Yes | Yes | Yes |
| View system metrics | Yes | Yes | Yes |
| Approve investigation | No | Yes | Yes |
| Reject investigation | No | Yes | Yes |
| Manage FP patterns | No | Yes | Yes |
| Activate kill switch | No | No | Yes |
| Deactivate kill switch | No | No | Yes |
| Manage SIEM connectors | No | No | Yes |
| Modify system settings | No | No | Yes |
| Access test harness | Yes | Yes | Yes |

### Route-Level Enforcement

Protected routes are defined in `_PROTECTED_PATTERNS`:

| Method | Path Prefix | Minimum Role |
|--------|-------------|-------------|
| POST | `/api/investigations/` | `senior_analyst` |

The `require_role()` decorator can be applied to individual routes for fine-grained control.

---

## Adversarial AI Defenses

### Context Gateway Pipeline

The Context Gateway implements a layered defense against adversarial manipulation of LLM interactions.

#### Layer 1: Injection Classification

The `RegexInjectionClassifier` scans all user-provided content for injection patterns:

| Risk Level | Action | Examples |
|-----------|--------|---------|
| NONE | PASS | Normal alert content |
| LOW | PASS | Minor suspicious patterns |
| MEDIUM | SUMMARIZE | Possible injection, lossy transform applied |
| HIGH | QUARANTINE | Clear injection attempt, block immediately |

#### Layer 2: Content Transformation

| Classification Action | Behaviour |
|----------------------|-----------|
| PASS | Content passes through unchanged |
| SUMMARIZE | Lossy summarisation strips potential injection payloads while preserving security facts |
| QUARANTINE | Content blocked entirely; `injection.quarantined` audit event emitted; human review required |

Design decision: **No redaction markers** are used. Replacing injections with `[REDACTED]` tokens would create a tuning oracle that attackers could exploit to refine their injection payloads.

#### Layer 3: Structured Evidence Isolation

All untrusted alert data is wrapped in XML delimiters:

```xml
<untrusted_alert_data>
  <alert_title>...</alert_title>
  <alert_description>...</alert_description>
  <entities_json>...</entities_json>
</untrusted_alert_data>
```

This creates a clear boundary between trusted system instructions and untrusted input.

#### Layer 4: Output Validation (Deny-by-Default)

LLM outputs are validated against:
1. **Output schema**: JSON structure validation if schema provided
2. **Taxonomy allowlist**: Any technique ID in the output is checked against the `taxonomy_ids` table
3. **Quarantine**: Unknown/hallucinated technique IDs are stripped from the output using word-boundary regex
4. **Audit trail**: Each quarantined ID generates a `technique.quarantined` audit event

---

## PII Redaction and Deanonymisation

### Redaction Process

The `pii_redactor` module (`context_gateway/pii_redactor.py`) identifies and replaces PII before content reaches the LLM:

| PII Type | Pattern | Replacement |
|----------|---------|-------------|
| Email addresses | RFC 5322 pattern | `[EMAIL_1]`, `[EMAIL_2]`, ... |
| IP addresses | IPv4/IPv6 | `[IP_1]`, `[IP_2]`, ... |
| Names | Named entity patterns | `[PERSON_1]`, `[PERSON_2]`, ... |
| SSNs | `\d{3}-\d{2}-\d{4}` | `[SSN_1]`, ... |
| Credit cards | Luhn-valid card patterns | `[CC_1]`, ... |

### Deanonymisation

After LLM processing and output validation, the `deanonymise_text()` function restores original PII values using the `RedactionMap` generated during redaction. This ensures:
- PII never reaches the LLM provider
- Response content contains correct original values
- The RedactionMap is never persisted or logged

---

## Audit Trail

### Hash-Chain Architecture

Every automated decision in ALUSKORT is recorded in a tamper-evident audit trail using SHA-256 hash chains.

```
+---Genesis---+     +---Record 1--+     +---Record 2--+
| seq: 0      |     | seq: 1      |     | seq: 2      |
| prev: 0x00..| --> | prev: hash0 | --> | prev: hash1 |
| hash: hash0 |     | hash: hash1 |     | hash: hash2 |
+-----------  +     +-------------+     +-------------+
```

### Chain Properties

| Property | Value |
|----------|-------|
| Hash algorithm | SHA-256 |
| Genesis hash | `0x0000...0000` (64 zeros) |
| Chain scope | Per-tenant |
| State tracking | `audit_chain_state` table (tenant_id, last_sequence, last_hash) |
| Record storage | `audit_records` table |
| Cold storage | MinIO S3-compatible (evidence packages) |

### Record Fields

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | UUID | Unique record identifier |
| `tenant_id` | string | Tenant that owns this record |
| `sequence_number` | integer | Monotonically increasing per-tenant |
| `previous_hash` | string | SHA-256 hash of the previous record |
| `record_hash` | string | SHA-256 hash of this record (excluding this field) |
| `timestamp` | ISO 8601 | Event timestamp |
| `event_type` | string | One of 40 `EventTaxonomy` values |
| `event_category` | string | decision, action, approval, security, system |
| `actor_type` | string | agent, human, system |
| `actor_id` | string | Identifier of the acting entity |
| `investigation_id` | string | Associated investigation (if applicable) |
| `context` | JSON | Event-specific metadata |

### Chain Verification

The `verify_chain()` function validates:
1. Each record's `record_hash` matches its computed SHA-256
2. Each record's `previous_hash` matches the prior record's `record_hash`
3. Sequence numbers are contiguous with no gaps

---

## Kill Switch and Emergency Procedures

### Kill Switch Dimensions

The `KillSwitchManager` (`orchestrator/kill_switch.py`) provides 4-dimension emergency kill switches backed by Redis:

| Dimension | Redis Key Pattern | Effect |
|-----------|-------------------|--------|
| `tenant` | `kill_switch:tenant:{id}` | Blocks ALL FP auto-close for the tenant |
| `pattern` | `kill_switch:pattern:{id}` | Blocks a specific FP pattern |
| `technique` | `kill_switch:technique:{id}` | Blocks FP for a MITRE technique |
| `datasource` | `kill_switch:datasource:{src}` | Blocks FP from a data source |

### Kill Switch Behaviour

- Any active kill switch in ANY dimension blocks FP auto-close
- Kill switches are stored in Redis for sub-millisecond lookup
- Activation/deactivation emits audit events (`kill_switch.activated`, `kill_switch.deactivated`)
- Fail-open: if Redis is unreachable, auto-close proceeds (logged as warning)

### Activation Procedure

1. Admin navigates to Dashboard Settings
2. Selects kill switch dimension and value
3. Provides reason for activation
4. System records metadata: `activated_by`, `activated_at`, `reason`
5. All matching FP evaluations are blocked immediately
6. Audit event emitted to `audit.events`

---

## Secret Management

### Development (Docker Compose)

| Secret | Source | Location |
|--------|--------|----------|
| `ANTHROPIC_API_KEY` | Host environment variable | `docker-compose.yml` env |
| `POSTGRES_PASSWORD` | Hardcoded (`localdev`) | `docker-compose.yml` |
| `NEO4J_AUTH` | Hardcoded (`neo4j/localdev`) | `docker-compose.yml` |
| `MINIO_ROOT_USER/PASSWORD` | Hardcoded (`minioadmin`) | `docker-compose.yml` |

### Production (Kubernetes)

| Secret | Source | K8s Resource |
|--------|--------|-------------|
| `ANTHROPIC_API_KEY` | K8s Secret | `aluskort-secrets` |
| `POSTGRES_DSN` | K8s Secret | `aluskort-secrets` |
| `NEO4J_AUTH` | K8s Secret | `aluskort-secrets` |
| SIEM credentials | K8s Secret | Per-adapter secrets |

All secrets are mounted via `secretRef` in deployment specs. No secrets are stored in ConfigMaps.

---

## Network Security

### Kubernetes Namespace Isolation

| Property | Value |
|----------|-------|
| Namespace | `aluskort` |
| Service type | `ClusterIP` (no external exposure except Dashboard) |
| Ingress | Dashboard only, via Ingress controller |

### Service Communication Matrix

| Source | Destination | Protocol | Port |
|--------|-------------|----------|------|
| Dashboard | PostgreSQL | TCP | 5432 |
| Dashboard | Redis | TCP | 6379 |
| Orchestrator | Context Gateway | HTTP | 8030 |
| Orchestrator | PostgreSQL | TCP | 5432 |
| Orchestrator | Redis | TCP | 6379 |
| Orchestrator | Qdrant | HTTP | 6333 |
| Orchestrator | Neo4j | Bolt | 7687 |
| Context Gateway | Anthropic API | HTTPS | 443 |
| Context Gateway | PostgreSQL | TCP | 5432 |
| LLM Router | Context Gateway | HTTP | 8030 |
| All services | Kafka | TCP | 9092 |
| Audit Service | MinIO | HTTP | 9000 |
