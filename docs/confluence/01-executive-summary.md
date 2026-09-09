# Executive Summary

## What is ALUSKORT?

ALUSKORT is an autonomous Security Operations Centre (SOC) platform that uses tiered LLM reasoning to investigate, triage, and respond to security alerts at machine speed. It ingests alerts from enterprise SIEMs (Microsoft Sentinel, Elastic SIEM, Splunk), runs them through a multi-agent investigation pipeline with IOC extraction, context enrichment, CTEM correlation, and MITRE ATLAS adversarial-AI mapping, then produces analyst-ready verdicts with recommended response actions.

The platform is purpose-built for hybrid IT/OT environments where both traditional cyber threats and adversarial AI attacks against machine-learning systems must be detected and investigated. A human-in-the-loop approval gate ensures that high-impact response actions are never executed without analyst consent, while a false-positive short-circuit mechanism automatically closes known benign patterns with >98% accuracy.

---

## Business Value Proposition

- **Reduce Mean Time to Detect (MTTD)** from minutes/hours to under 30 seconds by automating initial triage and IOC extraction
- **Eliminate alert fatigue** through automated false-positive closure, freeing analysts to focus on true positives
- **Cover the AI threat surface** with MITRE ATLAS detection rules that traditional SOC tooling does not address
- **Unify IT and OT security** with Purdue-model-aware CTEM scoring and consequence-weighted severity
- **Ensure auditability** via a tamper-evident SHA-256 hash-chain audit trail for every automated decision
- **Control LLM costs** with a 4-tier model routing architecture and hard spend caps, keeping monthly costs between $250--$400
- **Maintain human oversight** through severity-aware approval gates, kill switches, and shadow-mode deployment
- **Accelerate analyst onboarding** with a modern HTMX dashboard showing full investigation context in a single pane

---

## Key Metrics Targets

| Metric | Target | Description |
|--------|--------|-------------|
| MTTD (Mean Time to Detect) | < 30 seconds | From alert ingestion to initial classification |
| FP Auto-Close Rate | > 98% | Percentage of known false positives closed without human intervention |
| MTTR (Mean Time to Respond) | < 15 minutes | From alert ingestion to response action execution |
| Automation Rate | > 80% | Percentage of alerts fully handled without human intervention |
| Missed True Positives | < 1% | Percentage of genuine threats incorrectly classified as FP |
| Monthly LLM Cost | $250 -- $400 | Total Anthropic API spend per month at steady state |

---

## Architecture at a Glance

```
+------------------------------------------------------------------+
|                    PRESENTATION LAYER                              |
|  Dashboard (FastAPI + HTMX)  |  WebSocket  |  REST API           |
+------------------------------------------------------------------+
|                    REASONING LAYER                                 |
|  Orchestrator  |  LLM Router  |  Context Gateway  |  Agents      |
|  (State Machine)  (4-Tier)     (Sanitise+Validate)  (6 Agents)   |
+------------------------------------------------------------------+
|                    DATA LAYER                                      |
|  PostgreSQL 16  |  Redis 7  |  Qdrant  |  Neo4j 5  |  MinIO     |
|  (State+MITRE)   (Cache+KS)  (Vectors)  (Graphs)   (Audit/S3)   |
+------------------------------------------------------------------+
|                    NORMALISATION LAYER                             |
|  Entity Parser  |  CTEM Normaliser  |  ATLAS Detection Engine    |
+------------------------------------------------------------------+
|                    INGEST LAYER                                    |
|  Sentinel Adapter  |  Elastic Adapter  |  Splunk Adapter         |
|  Kafka/Redpanda (31 topics)                                       |
+------------------------------------------------------------------+
```

---

## Current Status

| Sprint | Focus | Status |
|--------|-------|--------|
| Sprint 1 | Core pipeline (Entity Parser, Orchestrator, Context Gateway, LLM Router) | Complete |
| Sprint 2 | CTEM Normaliser, ATLAS Detection, Batch Scheduler, Audit Service | Complete |
| Sprint 3 | SIEM Adapters (Sentinel, Elastic, Splunk), Analyst Dashboard | Complete |
| Sprint 4 | Adversarial review hardening, controlled-pilot readiness | In validation |

Core implementation is complete through the analyst-approved Sentinel write-back path. Controlled-pilot validation, outage exercises, and the 48-hour soak remain before production sign-off. The local test harness provides synthetic scenarios spanning APT, ransomware, insider threat, cloud compromise, and adversarial AI attack categories; it is disabled in production.
