# Access Control Policy

**Document ID:** ALUSKORT-ISMS-03
**Version:** 1.0
**Classification:** Confidential
**Owner:** Chief Information Security Officer (CISO)
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.5.15--5.18, A.8.2--8.5

---

## 1. Purpose

This document defines the access control policy for the ALUSKORT SOC Platform, including the role-based access control (RBAC) model, authentication mechanisms, privilege management, multi-tenant isolation, and access review procedures.

---

## 2. Access Control Policy (A.5.15)

### 2.1 Principles

1. **Least privilege** -- users receive only the minimum permissions necessary for their role.
2. **Need-to-know** -- access to tenant data is restricted to authorised personnel with a legitimate operational need.
3. **Separation of duties** -- critical actions require multiple authorised individuals.
4. **Default deny** -- access is denied unless explicitly granted by RBAC policy.
5. **Tenant isolation** -- users of one tenant cannot access data belonging to another tenant.

### 2.2 Access Control Model

The ALUSKORT platform implements Role-Based Access Control (RBAC) with three hierarchical roles:

```
admin (highest privilege)
  └── senior_analyst
        └── analyst (lowest privilege)
```

Higher roles inherit all permissions of lower roles.

---

## 3. RBAC Role Definitions (A.5.18)

### 3.1 Role Descriptions

| Role | Description | Typical Assignees | Maximum Count |
|---|---|---|---|
| `analyst` | Standard SOC analyst with read access to alerts, investigations, and cases assigned to their tenant. Can add investigation notes, request escalation, and view dashboards. | L1 Analysts, L2 Analysts | Unlimited (per-tenant) |
| `senior_analyst` | Senior analyst with authority to approve/reject AI recommendations, manage investigations, create/approve FP patterns (with two-person approval), and export evidence packages. | L3 Senior Analysts | Min. 2 per tenant (for two-person approval) |
| `admin` | Full platform administrator with access to all configuration, tenant management, user management, system settings, kill switch, and audit trail. | CISO, SOC Manager, Platform Engineering Lead | Max. 5 total |

### 3.2 Role Permissions Matrix

| Resource / Action | `analyst` | `senior_analyst` | `admin` |
|---|---|---|---|
| **Alerts** | | | |
| View alerts (own tenant) | Yes | Yes | Yes |
| View alerts (all tenants) | No | No | Yes |
| Update alert status | Yes | Yes | Yes |
| Delete alerts | No | No | Yes |
| **Investigations** | | | |
| View investigations (own tenant) | Yes | Yes | Yes |
| Trigger manual investigation | No | Yes | Yes |
| View AI agent decision chain | Yes (summary) | Yes (full) | Yes (full) |
| Add investigation notes | Yes | Yes | Yes |
| **AI Recommendations** | | | |
| View recommendations | Yes | Yes | Yes |
| Approve recommendations | No | Yes | Yes |
| Reject recommendations | No | Yes | Yes |
| Override AI confidence threshold | No | No | Yes |
| **Response Actions** | | | |
| View pending actions | Yes | Yes | Yes |
| Approve response actions | No | Yes | Yes |
| Execute manual response | No | Yes | Yes |
| **False Positive Patterns** | | | |
| View FP patterns | Yes | Yes | Yes |
| Propose FP pattern | No | Yes | Yes |
| Approve FP pattern (two-person) | No | Yes | Yes |
| Delete FP pattern | No | No | Yes |
| Reaffirm expiring patterns | No | Yes | Yes |
| **Cases** | | | |
| View cases (own tenant) | Yes | Yes | Yes |
| Create cases | Yes | Yes | Yes |
| Close cases | No | Yes | Yes |
| Export evidence packages | No | Yes | Yes |
| **Users and Tenants** | | | |
| View own profile | Yes | Yes | Yes |
| Manage users (own tenant) | No | No | Yes |
| Create/modify tenants | No | No | Yes |
| Set tenant quotas | No | No | Yes |
| **System Configuration** | | | |
| View system health | No | Yes (limited) | Yes |
| Modify LLM routing config | No | No | Yes |
| Modify Context Gateway rules | No | No | Yes |
| Modify ATLAS detection rules | No | No | Yes |
| **Kill Switch** | | | |
| View kill switch status | No | Yes | Yes |
| Activate kill switch | No | No | Yes |
| Deactivate kill switch | No | No | Yes |
| **Audit Trail** | | | |
| View audit records (own actions) | Yes | Yes | Yes |
| View audit records (own tenant) | No | Yes | Yes |
| View audit records (all tenants) | No | No | Yes |
| Verify hash-chain integrity | No | No | Yes |
| Export audit packages | No | Yes | Yes |
| **Dashboard** | | | |
| View investigation dashboard | Yes | Yes | Yes |
| View analytics dashboard | No | Yes | Yes |
| View admin dashboard | No | No | Yes |

---

## 4. Authentication Mechanisms (A.8.5)

### 4.1 External User Authentication

#### 4.1.1 Local Development Authentication

| Aspect | Implementation |
|---|---|
| Mechanism | X-User-Role HTTP header (trusted proxy model) |
| Identity source | Upstream reverse proxy / API gateway |
| Header format | `X-User-Role: analyst\|senior_analyst\|admin` |
| User identity | `X-User-Id: <uuid>` |
| Tenant identity | `X-Tenant-Id: <uuid>` |
| Transport security | TLS 1.3 (external); header injection mitigated by gateway stripping |
| Limitations | Disabled for production; a valid explicit role is required and no administrator default exists |

#### 4.1.2 Production Authentication

| Aspect | Implementation |
|---|---|
| Mechanism | OpenID Connect (OIDC) |
| Identity provider | Single-tenant Microsoft Entra ID |
| Token type | JWT (JSON Web Token) with RS256 signature |
| Token lifetime | Access token: 15 minutes; Refresh token: 8 hours |
| Claims mapping | `oid` → user ID; `tid` → configured tenant; application `roles` → platform role |
| MFA requirement | Required for `senior_analyst` and `admin` roles |
| Session management | Stateless JWT validation; token revocation via short lifetimes + blocklist |

The application rejects cross-tenant, application-only, invalid-audience, and
invalid-issuer tokens. Production startup fails unless Entra mode is selected.
MFA and Conditional Access enforcement remain identity-provider controls.

### 4.2 Inter-Service Authentication

| Aspect | Implementation |
|---|---|
| Mechanism | Mutual TLS (mTLS) |
| Certificate authority | Internal CA (cert-manager on Kubernetes) |
| Certificate lifetime | 24 hours (auto-rotated) |
| Identity verification | Service name in certificate CN/SAN |
| Trust model | All services trust only the internal CA |
| Fallback | None -- mTLS is mandatory for inter-service communication |

### 4.3 API Authentication

| API Consumer | Authentication Method |
|---|---|
| SIEM adapters (inbound) | API key + IP allowlist (MVP); mTLS (production) |
| Anthropic Claude API (outbound) | API key in Authorization header via TLS 1.3 |
| Monitoring endpoints | Service mesh identity (Prometheus scraping) |
| Health check endpoints | Unauthenticated (limited to /health, /ready) |

---

## 5. Privileged Access Management (A.5.18)

### 5.1 Admin Role Controls

| Control | Implementation |
|---|---|
| Maximum admin accounts | 5 accounts globally |
| Approval for admin grant | CISO written approval required |
| Admin action logging | All admin actions recorded in audit trail with hash-chain integrity |
| Kill switch activation | Requires admin role + documented justification; recorded in audit trail |
| Break-glass procedure | Emergency admin access via sealed credentials; requires two-person unsealing; automatically expires after 4 hours |
| Admin access review | Quarterly review by CISO |
| Separation of duties | Admins cannot self-approve FP patterns or their own role changes |

### 5.2 Service Account Management

| Control | Implementation |
|---|---|
| Service accounts | One mTLS identity per microservice |
| Service permissions | Service-level RBAC (e.g., Audit Service can only write audit records) |
| Credential storage | Kubernetes Secrets with etcd encryption |
| Rotation | Automatic via cert-manager (24-hour certificate lifecycle) |
| Monitoring | Alert on certificate expiry, failed mTLS handshakes |

---

## 6. Multi-Tenant Access Isolation (A.8.3)

### 6.1 Tenant Isolation Model

```
                ┌─────────────────────────────────────┐
                │           ALUSKORT Platform          │
                │                                      │
                │  ┌───────────┐    ┌───────────┐      │
                │  │ Tenant A  │    │ Tenant B  │      │
                │  │           │    │           │      │
                │  │ Users     │    │ Users     │      │
                │  │ Alerts    │    │ Alerts    │      │
                │  │ Cases     │    │ Cases     │      │
                │  │ Audit     │    │ Audit     │      │
                │  │ Quotas    │    │ Quotas    │      │
                │  └───────────┘    └───────────┘      │
                │                                      │
                │  Shared infrastructure, isolated data │
                └─────────────────────────────────────┘
```

### 6.2 Isolation Controls

| Layer | Control | Implementation |
|---|---|---|
| Application | Tenant context injection | Every API request carries `X-Tenant-Id`; enforced at middleware level |
| Database | Tenant-scoped queries | All database queries include `WHERE tenant_id = :tenant_id`; no cross-tenant joins |
| Database | Row-level security (planned) | PostgreSQL RLS policies enforce tenant isolation at database level |
| Cache | Tenant-prefixed keys | Redis keys prefixed with `tenant:{id}:` to prevent key collision |
| Message bus | Tenant topic filtering | Kafka consumers filter messages by tenant_id field |
| Vector DB | Tenant collection isolation | Qdrant collections scoped per tenant |
| Graph DB | Tenant graph partitioning | Neo4j tenant_id property on all nodes; query filters enforced |
| Object storage | Tenant bucket separation | MinIO buckets per tenant: `tenant-{id}/` prefix |
| LLM | Tenant quota enforcement | Spend guard tracks per-tenant LLM usage against tier limits |
| Audit | Per-tenant hash chains | Separate hash-chain per tenant with independent genesis blocks |

### 6.3 Tenant Quota Configuration

| Tier | LLM Calls per Hour | Max Concurrent Investigations | Data Retention |
|---|---|---|---|
| Premium | 500 | 50 | 365 days |
| Standard | 100 | 20 | 180 days |
| Trial | 20 | 5 | 30 days |

---

## 7. Session Management

| Control | Implementation |
|---|---|
| Session mechanism | JWT tokens (stateless) in production; session cookies for dashboard |
| Session timeout (idle) | 30 minutes |
| Session timeout (absolute) | 8 hours |
| Concurrent sessions | Maximum 3 per user |
| Session termination | Logout invalidates refresh token; access token expires naturally |
| Dashboard WebSocket | Re-authenticated every 15 minutes; connection closed on token expiry |
| Admin session | Reduced timeout: 15 minutes idle, 4 hours absolute |

---

## 8. Access Review Procedures (A.5.18)

### 8.1 Review Schedule

| Review Type | Frequency | Reviewer | Scope |
|---|---|---|---|
| Admin role review | Quarterly | CISO | All admin accounts; verify continued need |
| Senior analyst role review | Quarterly | SOC Manager | All senior_analyst accounts per tenant |
| Analyst role review | Semi-annually | SOC Manager | All analyst accounts per tenant |
| Service account review | Quarterly | Platform Eng Lead | All mTLS identities and service permissions |
| API key review | Quarterly | Security Architect | All API keys (SIEM adapters, Anthropic) |
| Tenant access review | Semi-annually | CISO | Cross-tenant access audit; verify isolation |

### 8.2 Review Process

1. **Extract** -- generate access report from user management and audit trail systems
2. **Compare** -- verify each account against authorised personnel register and role requirements
3. **Identify** -- flag accounts that are inactive (> 30 days), have excessive permissions, or belong to departed personnel
4. **Remediate** -- disable/remove flagged accounts; adjust permissions as needed
5. **Document** -- record review findings, actions taken, and next review date
6. **Attest** -- reviewer signs off on review completion

### 8.3 Joiner/Mover/Leaver Process

| Event | Actions | Timeline |
|---|---|---|
| **Joiner** | Create account with minimum required role; assign to tenant; complete security training; record in audit trail | Within 2 business days of start date |
| **Mover** (role change) | Review current permissions; adjust role; update tenant assignment if applicable; record in audit trail | Within 1 business day of role change |
| **Leaver** | Disable account immediately; revoke all active sessions; review recent audit trail for anomalies; remove within 24 hours | Same day as departure; review within 24 hours |

---

## 9. Access Control Monitoring

| Metric | Source | Alert Threshold |
|---|---|---|
| Failed authentication attempts | Audit trail | > 5 failures in 10 minutes per user |
| Admin role usage | Audit trail | Any admin action outside business hours |
| Cross-tenant access attempts | Application logs | Any occurrence (should be 0) |
| Privilege escalation attempts | Application logs | Any unauthorised role elevation attempt |
| Dormant accounts | User management | Account inactive > 30 days |
| mTLS handshake failures | Service mesh logs | > 10 failures in 5 minutes |
| API key usage anomalies | API gateway logs | Usage pattern deviation > 3 std dev |

---

## 10. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed quarterly for RBAC model changes and annually for full policy review.*
