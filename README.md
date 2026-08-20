<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white" alt="Python 3.12">
  <img src="https://img.shields.io/badge/FastAPI-0.109+-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white" alt="PostgreSQL 16">
  <img src="https://img.shields.io/badge/Terraform-AWS-7B42BC?logo=terraform&logoColor=white" alt="Terraform">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-Proprietary-red" alt="License">
</p>

# ALUSKORT — AI-Powered SOC Platform

**Cloud-Neutral Security Reasoning Control Plane** by [Applied Computing Technologies](https://github.com/scs-labrat)

ALUSKORT is an autonomous Security Operations Center (SOC) platform that uses LLM-driven investigation graphs to triage, enrich, and resolve security alerts with minimal analyst intervention. It reduces Mean Time to Detect (MTTD) to under 30 seconds and automates 80%+ of investigations end-to-end.

---

## Architecture

```
                         ┌──────────────┐
                         │   Analyst     │
                         │  Dashboard    │
                         │  (FastAPI)    │
                         └──────┬───────┘
                                │
                     ┌──────────┴──────────┐
                     │    Orchestrator      │
                     │  (LangGraph Agent)   │
                     └──┬───┬───┬───┬──────┘
                        │   │   │   │
              ┌─────────┘   │   │   └─────────┐
              ▼             ▼   ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Entity  │ │ Context  │ │   LLM    │ │  CTEM    │
        │  Parser  │ │ Gateway  │ │  Router  │ │Normaliser│
        └──────────┘ └──────────┘ └──────────┘ └──────────┘
              │             │           │             │
    ┌─────────┴─────────────┴───────────┴─────────────┴──────┐
    │                    Data Layer                           │
    │  PostgreSQL │ Redis │ Kafka │ Qdrant │ Neo4j │ MinIO   │
    └────────────────────────────────────────────────────────┘
```

## Key Capabilities

| Capability | Description |
|---|---|
| **Autonomous Investigation** | LLM-driven graph orchestrator triages alerts through enrichment, classification, and response |
| **CISO Executive Dashboard** | 8 KPIs, 7 interactive Chart.js visualisations (click-to-expand, zoom, export) |
| **MITRE ATT&CK Mapping** | Automated tactic/technique classification for every investigation |
| **CTEM Exposure Management** | Continuous Threat Exposure Management with severity-based remediation tracking |
| **ATLAS Adversarial AI** | Detection of prompt injection, model manipulation, and AI-specific threats |
| **Canary Rollout Control** | Progressive rule deployment (shadow → 10% → 25% → 50% → 100%) with auto-rollback |
| **Shadow Mode Testing** | Test new rules against live traffic without affecting production outcomes |
| **SIEM Integration** | Native adapters for Elastic SIEM, Splunk, and Microsoft Sentinel |
| **False Positive Learning** | Automated FP pattern detection with governance-approved suppression rules |
| **Multi-LLM Routing** | Provider-agnostic routing with fallback, cost tracking, and model health monitoring |
| **Human-in-the-Loop** | Approval workflows for high-severity containment actions |
| **Full Audit Trail** | Immutable, chain-verified audit records for ISO 27001 compliance |

## Dashboard Pages

The web UI includes 20 pages across four navigation groups:

| Group | Pages |
|---|---|
| **Core** | CISO Executive, Overview Metrics, Investigations, Approvals |
| **Threat Intel** | CTEM Exposures, CTI / IOC Feeds, Adversarial AI, FP Patterns, Playbooks |
| **Platform** | LLM Health, Shadow Mode, Canary Rollout, Batch Jobs, Audit Trail, Connectors |
| **Admin** | Users & Roles, Settings (LLM Providers/Models CRUD), Test Harness |

---

## Quick Start (Local Development)

### Prerequisites

- Docker & Docker Compose
- Python 3.12+ (for running tests outside Docker)

### 1. Start Infrastructure + Dashboard

```bash
# Start Postgres, Redis, and the dashboard
docker-compose up -d postgres redis dashboard

# Dashboard available at http://localhost:8080
```

### 2. Start All Services (Full Stack)

```bash
# Requires ANTHROPIC_API_KEY for LLM features
export ANTHROPIC_API_KEY=sk-ant-...

docker-compose --profile services up -d
```

### 3. Enable Microsoft Sentinel Ingestion

Copy `.env.example` to `.env`; set the Sentinel workspace ID, subscription,
resource group, workspace name, and Microsoft Entra identity variables. Set
`DASHBOARD_ENTRA_CLIENT_ID` to the dashboard API app registration and define
the `Aluskort.Analyst`, `Aluskort.SeniorAnalyst`, and `Aluskort.Admin` app
roles. Then start the application and Sentinel profiles:

```bash
docker compose --profile services --profile sentinel up -d
curl --fail http://localhost:8032/ready
curl --fail http://localhost:8033/ready
```

The polling connector reads Sentinel `SecurityAlert` records through the Azure
Monitor Log Analytics API, publishes canonical alerts to `alerts.raw`, and
stores its durable watermark and deduplication state in PostgreSQL.
After an authorised analyst approves an investigation, the write-back worker
uses a transactional outbox to add one deterministic summary comment and the
`ALUSKORT-Investigated` label to the originating incident. The Azure identity
must be allowed to read/update Sentinel incidents and create incident comments.

### 3. Run Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

### Service Ports

| Service | Port | Endpoint |
|---|---|---|
| Dashboard | 8080 | `http://localhost:8080` |
| Context Gateway | 8030 | `http://localhost:8030` |
| LLM Router | 8031 | `http://localhost:8031` |
| Sentinel Adapter | 8032 | `http://localhost:8032` |
| Sentinel Write-back | 8033 | `http://localhost:8033` |
| PostgreSQL | 5432 | `postgresql://aluskort:localdev@localhost:5432/aluskort` |
| Redis | 6379 | `redis://localhost:6379` |
| Kafka (Redpanda) | 9092 | `localhost:9092` |
| Qdrant | 6333 | `http://localhost:6333` |
| Neo4j | 7474 / 7687 | `http://localhost:7474` |
| MinIO | 9000 / 9001 | `http://localhost:9001` (console) |

---

## Production Deployment (AWS)

ALUSKORT ships with a complete Terraform configuration and interactive deployment wizard for AWS.

### Infrastructure Provisioned

- **VPC** — 3 availability zones, public/private subnets, NAT gateway, VPC flow logs
- **ECS Fargate** — All 6 services with auto-scaling, circuit breaker rollback
- **RDS PostgreSQL 16** — Multi-AZ, encrypted, 14-day backups, performance insights
- **ElastiCache Redis 7** — Encrypted at rest/transit, automatic failover
- **MSK Kafka 3.6** — 3 brokers, TLS encryption, CloudWatch logging
- **ALB** — HTTPS with TLS 1.3, access logs to S3
- **ECR** — Container registries with image scanning and lifecycle policies
- **Secrets Manager** — API keys and database credentials
- **CloudWatch** — Alarms (CPU, memory, storage, connections), SNS alerts, operational dashboard

### Deploy with Wizard

```bash
cd infra/terraform
bash deploy.sh
```

The wizard prompts for:

1. **AWS region** and environment (prod/staging/dev)
2. **Domain & SSL** — optional ACM certificate for HTTPS
3. **Database** — instance class and master password
4. **Cache & Streaming** — Redis and Kafka instance sizes
5. **API keys** — Anthropic API key
6. **Monitoring** — alarm notification email
7. **ECS sizing** — replica counts per service

Estimated cost: **~$365–610/month** depending on sizing choices.

```bash
# Other commands
bash deploy.sh --plan-only    # Generate config and plan without applying
bash deploy.sh --skip-build   # Apply infra without building Docker images
bash deploy.sh --destroy      # Tear down all infrastructure
```

### Manual Terraform

```bash
cd infra/terraform
terraform init
# Edit terraform.tfvars with your values
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

---

## Project Structure

```
├── atlas_detection/        # MITRE ATLAS adversarial AI detection engine
├── batch_scheduler/        # Scheduled batch job processing
├── context_gateway/        # LLM context assembly and prompt construction
├── ctem_normaliser/        # CTEM exposure normalisation pipeline
├── elastic_adapter/        # Elastic SIEM integration adapter
├── entity_parser/          # Alert entity extraction (IPs, domains, hashes)
├── llm_router/             # Multi-provider LLM routing with fallback
├── ops/                    # Operational tooling (kill switches, health)
├── orchestrator/           # LangGraph investigation orchestrator
│   └── agents/             # Investigation agent definitions
├── sentinel_adapter/       # Microsoft Sentinel integration adapter
├── splunk_adapter/         # Splunk SIEM integration adapter
├── services/
│   ├── audit_service/      # Immutable audit trail service
│   └── dashboard/          # FastAPI + HTMX + Tailwind analyst dashboard
│       ├── routes/         # 20 route modules
│       ├── templates/      # Jinja2 templates (per-page directories)
│       ├── middleware/      # RBAC authentication middleware
│       └── static/         # Static assets
├── shared/                 # Shared libraries
│   ├── adapters/           # SIEM adapter base classes
│   ├── audit/              # Audit trail producer library
│   ├── auth/               # JWT + RBAC utilities
│   ├── config/             # Configuration management
│   ├── db/                 # Database clients (Postgres, Redis, Qdrant, Neo4j)
│   └── schemas/            # Pydantic data models
├── tests/                  # Pytest suite (unit + integration + security)
├── infra/
│   ├── migrations/         # PostgreSQL migrations (001–013)
│   ├── terraform/          # AWS production infrastructure
│   │   ├── modules/        # VPC, ECS, RDS, ElastiCache, MSK, ALB, ECR, Secrets, Monitoring
│   │   └── deploy.sh       # Interactive deployment wizard
│   ├── k8s/                # Kubernetes manifests (alternative deployment)
│   ├── prometheus/         # Prometheus monitoring config
│   └── s3-lifecycle/       # S3 evidence retention policies
├── docs/
│   ├── confluence/         # Architecture & operations documentation (15 files)
│   └── iso27001/           # ISO 27001 compliance documentation (14 files)
├── docker-compose.yml      # Local development stack
├── Dockerfile              # Multi-service container image
└── pyproject.toml          # Python project configuration
```

## Database Migrations

Migrations run automatically on first `docker-compose up` via the Postgres init directory. For production:

```bash
# Migrations are in infra/migrations/ (001-019)
# Applied in order by filename during container init
ls infra/migrations/
```

| Migration | Purpose |
|---|---|
| 001 | Core tables (investigation_state, alerts) |
| 002 | CTEM exposure tables |
| 003–004 | ATLAS detection and telemetry |
| 005 | Taxonomy seed data |
| 006–007 | Audit records and chain state |
| 008 | FP governance rules |
| 009 | Embedding migration |
| 010 | Incident memory (rare events) |
| 011 | Dashboard sessions |
| 012 | Connector configuration |
| 013 | LLM providers and models |
| 014–017 | TI chunks, analyst feedback, tenant spend caps, organisation assets |
| 018 | Durable Sentinel polling checkpoints and deduplication |
| 019 | Durable analyst approvals and Sentinel write-back outbox |

## CI/CD

GitHub Actions pipeline (`.github/workflows/ci-cd.yml`):

- **Test** — Python 3.12, full production-tree branch coverage (62.5% baseline, 85% pilot target), Postgres 16 + Redis 7
- **Validate** — Docker Compose resolution and Terraform formatting/syntax
- **Build** — Docker image build and push to GHCR

## Documentation

| Document Set | Location | Contents |
|---|---|---|
| **Confluence** | `docs/confluence/` | Architecture, service catalogue, investigation workflow, data model, LLM architecture, security controls, CTEM, ATLAS, dashboard guide, deployment, operations runbook, API reference, testing guide |
| **ISO 27001** | `docs/iso27001/` | ISMS scope, security policy, risk assessment, access control, cryptographic controls, operations security, communications security, supplier relationships, incident management, business continuity, data protection, AI-specific controls, statement of applicability (93 Annex A controls), audit trail specification |

## Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Python 3.12 |
| **Web Framework** | FastAPI + Jinja2 + HTMX |
| **Styling** | Tailwind CSS |
| **Charts** | Chart.js 4.4.7 + chartjs-plugin-zoom |
| **Database** | PostgreSQL 16 (asyncpg) |
| **Cache** | Redis 7 (hiredis) |
| **Streaming** | Apache Kafka (confluent-kafka / Redpanda for dev) |
| **Vector Store** | Qdrant |
| **Graph DB** | Neo4j 5 |
| **Object Store** | MinIO (dev) / S3 (prod) |
| **LLM** | Anthropic Claude (primary), OpenAI (fallback) |
| **Container** | Docker, ECS Fargate |
| **IaC** | Terraform (AWS), Kubernetes manifests |
| **CI/CD** | GitHub Actions |
| **Monitoring** | CloudWatch, Prometheus |

---

<p align="center">
  <sub>Built by <a href="https://github.com/scs-labrat">Applied Computing Technologies</a></sub>
</p>
