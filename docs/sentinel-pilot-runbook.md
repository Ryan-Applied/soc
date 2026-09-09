# Microsoft Sentinel Controlled Pilot Runbook

## Scope

This pilot ingests Sentinel alerts, performs an ALUSKORT investigation, waits
for an authorised analyst decision, and writes one summary comment and one
`ALUSKORT-Investigated` label to the source incident. It does not close the
Sentinel incident or execute containment actions.

## Azure prerequisites

1. Assign the runtime identity `Log Analytics Data Reader` (or a narrower custom
   role with workspace query and table read permissions) on the workspace.
2. Assign the write-back identity `Microsoft Sentinel Responder` on the
   workspace for incident read/write and comment creation.
3. Create a single-tenant dashboard API app registration with these app roles:
   `Aluskort.Analyst`, `Aluskort.SeniorAnalyst`, and `Aluskort.Admin`.
4. Prefer managed/workload identity. For a local pilot only, populate the
   service-principal values in `.env`.

References: [Log Analytics access](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access),
[Entra app roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps),
[Sentinel incident comments API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incident-comments/create-or-update?view=rest-securityinsights-2025-09-01).

## Required configuration

Populate `.env` from `.env.example`, including:

- `ANTHROPIC_API_KEY`
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and local-only `AZURE_CLIENT_SECRET`
- `DASHBOARD_ENTRA_CLIENT_ID`
- `SENTINEL_WORKSPACE_ID`
- `SENTINEL_SUBSCRIPTION_ID`
- `SENTINEL_RESOURCE_GROUP`
- `SENTINEL_WORKSPACE_NAME`

## Start and verify

Before starting, confirm `.env` exists and every required value above is
populated. `docker compose config --quiet` validates the resolved Compose file
without displaying secrets.

```bash
test -f .env
docker compose --profile services --profile sentinel config --quiet
docker compose --profile services --profile sentinel up -d --build
curl --fail http://localhost:8030/ready
curl --fail http://localhost:8032/ready
curl --fail http://localhost:8033/ready
```

The Sentinel adapter remains unready until its initial authenticated Log
Analytics query succeeds. The write-back service validates its Azure credential
during startup. A `503` at either endpoint is therefore a real pilot blocker,
not a warm-up success state.

Use a non-production Sentinel analytics rule or other approved synthetic source
to create a uniquely tagged alert. Confirm, in order:

1. `sentinel_ingested_alerts` contains its `SystemAlertId` once.
2. `investigation_state` contains one deterministic investigation for that
   tenant and alert.
3. The investigation reaches `awaiting_human` with its Sentinel source context.
4. A user holding `Aluskort.SeniorAnalyst` approves it.
5. `approval_decisions` records that user's Entra object ID and role.
6. `sentinel_writeback_outbox` reaches `completed`.
7. The Sentinel incident shows one ALUSKORT comment and label.

Restart the Sentinel adapter and submit the same alert again. The ingestion and
investigation counts must remain one, and the deterministic comment must be
updated rather than duplicated.

## Failure handling

- Transient Azure responses (`408`, `409`, `412`, `429`, and `5xx`) retry with
  exponential backoff.
- A write-back worker crash is recovered after its five-minute processing lease.
- Invalid payloads and work exceeding eight attempts enter `dead_letter` and
  require operator review.
- To stop write-back without stopping ingestion:

```bash
docker compose stop sentinel-writeback
```

No rollback step should delete Sentinel comments or labels automatically. Record
any manual cleanup in the incident audit trail.
