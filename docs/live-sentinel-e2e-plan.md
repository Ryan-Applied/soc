# Live Microsoft Sentinel End-to-End Delivery Plan

**Status:** In progress
**Target:** Controlled pilot
**Primary flow:** Microsoft Sentinel alert → ALUSKORT investigation → analyst approval → Sentinel incident comment/tag

## Progress ledger (2026-08-20)

- [x] CI runs on `master`; the complete test suite and measured coverage gate pass.
- [x] Docker Compose and Terraform formatting are validated in CI.
- [x] Sentinel has an executable Azure-identity poller with durable watermarking,
  overlap-window querying, alert deduplication, incident correlation, and readiness.
- [x] Sentinel correlation identifiers propagate into the investigation graph.
- [x] Critical worker health checks are real, and the orchestrator/CTEM workers fail
  startup when required live dependencies are unavailable.
- [x] Production orchestrator mock fallbacks are removed; it uses the Context
  Gateway HTTP service and real Postgres, Redis, and Qdrant clients.
- [x] Make downstream investigation creation idempotent across Kafka redelivery
  with deterministic IDs and persisted-stage recovery.
- [x] Replace trusted production role headers with single-tenant Entra token
  validation and disable the production test harness.
- [x] Persist analyst approval and actor evidence transactionally.
- [x] Implement idempotent Sentinel incident comment/tag write-back with retry,
  crash recovery, and a dead-letter state.
- [ ] Remove demo fallbacks from non-core dashboard administration pages.
- [ ] Run containerised synthetic-alert and outage scenarios, followed by the soak.

## Safety boundary

The pilot may enrich and classify real alerts, but it must not automatically
close Sentinel incidents or execute destructive containment actions. The first
write-back release is limited to comments, tags, and analyst-approved metadata
updates.

## Definition of done

1. A Sentinel `SecurityAlert` produces exactly one ALUSKORT investigation.
2. Polling-mode ingestion latency is less than 90 seconds.
3. The canonical alert and every downstream event retain the Sentinel alert and
   incident correlation identifiers.
4. Production services fail startup when required dependencies are unavailable;
   they never silently substitute mocks or demo data.
5. The investigation contains real enrichment, LLM classification, confidence,
   model/cost metadata, and an auditable decision chain.
6. The dashboard requires Microsoft Entra authentication and enforces RBAC.
7. Analyst approval is durable and records the actor and timestamp.
8. Approval writes an ALUSKORT summary comment and tag to the originating
   Sentinel incident.
9. Restarts and overlapping polling windows do not duplicate investigations or
   Sentinel updates.
10. Failed ingestion, processing, and write-back events are recoverable from a
    dead-letter queue.

## Delivery phases

### Phase 1 — Trustworthy baseline

- Run CI on the repository's default `master` branch.
- Pin the Python 3.12 test environment and install test dependencies from the
  project metadata.
- Resolve test failures and schema-contract drift.
- Measure coverage across all production packages, starting with the measured
  62.5% branch-coverage gate (62.73% measured) and ratcheting to at least 85%
  before pilot sign-off.
- Validate Docker Compose and infrastructure configuration in CI.

**Gate:** The complete suite is green in CI on three consecutive runs.

### Phase 2 — Operational Sentinel ingestion

- Add an executable `sentinel_adapter.service` process.
- Use the Azure Monitor Log Analytics API with managed/workload identity where
  available and client credentials only as a pilot fallback.
- Persist the polling watermark in Postgres, query with an overlap window, and
  deduplicate by `SystemAlertId`.
- Correlate `SecurityAlert` records with `SecurityIncident` and retain the
  incident name/ARM identifier required for write-back.
- Add health, readiness, metrics, audit events, and a dead-letter path.

**Gate:** A tagged synthetic Sentinel alert appears once on `alerts.raw` within
90 seconds and survives a connector restart without duplication.

### Phase 3 — Real investigation pipeline

- Run all migrations and seed the MITRE taxonomy and pilot playbooks.
- Wire real Kafka, Postgres, Redis, Qdrant, Context Gateway, and LLM Router
  clients.
- Remove production `AsyncMock`/`MagicMock` fallbacks.
- Propagate a correlation ID from Sentinel through Kafka, Postgres, audit, and
  dashboard records.
- Make consumer processing and persistence idempotent.

**Gate:** One Sentinel alert creates one investigation with real entities,
enrichment, classification, confidence, decision chain, and audit events.

### Phase 4 — Secured analyst workflow

- Replace trusted role headers and default-admin behaviour with Microsoft Entra
  OIDC.
- Disable the test harness and all demo-data fallbacks in production.
- Enforce tenant boundaries and RBAC on every read and mutation.
- Persist approval requests, decisions, actors, timestamps, and pending actions.

**Gate:** Unauthenticated requests fail and only authorised roles can approve a
response.

### Phase 5 — Safe Sentinel write-back

- Implement a dedicated Sentinel incident output connector using ARM IDs and
  ETags.
- Add an investigation summary comment and `ALUSKORT-Investigated` tag.
- Permit severity or owner changes only after explicit analyst approval.
- Retry transient errors, dead-letter permanent failures, and make write-back
  idempotent.

**Gate:** Approval produces exactly one traceable comment and tag on the
originating Sentinel incident.

### Phase 6 — Pilot validation

- Run at least 20 deterministic synthetic alert scenarios.
- Test duplicate delivery, restarts, Kafka/Postgres/Azure/LLM outages, prompt
  injection, tenant isolation, approval, and write-back retry behaviour.
- Complete a 48-hour soak with latency, cost, health, and dead-letter monitoring.
- Publish the operating runbook and rollback procedure.

**Gate:** All definition-of-done checks pass and the pilot owner approves go-live.

## Delivery estimate

The controlled pilot is expected to require 16–24 engineering days. Automatic
incident closure and external containment are separate releases that require
measured false-positive performance and an additional safety review.
