# RiskCompass - Real-Time Implementation Plan

**Repository:** https://github.com/Bhargav-2007/RiskCompass  
**Target:** Working, self-hostable, free/open-source Vulnerability Intelligence & Risk Management Platform

## 1. Goal

Transform RiskCompass from its current static/browser-based MVP into a backend-authoritative platform that:

- ingests real vulnerability intelligence;
- ingests real asset/SBOM/scanner findings;
- persists authoritative state in PostgreSQL;
- calculates contextual risk on the server;
- continuously reprioritizes findings when intelligence or asset context changes;
- pushes updates to connected users through WebSocket/SSE;
- supports authentication, RBAC, tenant isolation and audit logging;
- supports remediation workflow and verification;
- provides analytics, alerts and reports backed by real historical data;
- remains functional without paid APIs or proprietary AI services.

The uploaded project specification requires CVE/NVD, CVSS, EPSS, CISA KEV, CWE, exploit intelligence, asset context, dynamic risk scoring, explainability and continuous reprioritization.

## 2. Current Repository Baseline

The current GitHub README describes RiskCompass as a **static, browser-based MVP** and explicitly states that it does not perform live feeds or external integrations. The repository contains a React/Vite frontend, a FastAPI-oriented backend, ML scripts/tests, database code and GitHub Actions artifacts.

### Critical current-state problems to remove

1. Production UI depends on hard-coded/demo data.
2. Production risk must not be calculated only in the browser.
3. Simulated API responses must be replaced with database-backed services.
4. Trend/top-risk endpoints must read historical persisted records.
5. Remediation actions must persist and become verifiable.
6. ML labels must avoid leakage.
7. Demo mode must be isolated from production mode.

## 3. Non-Negotiable Rules

- PostgreSQL is the production source of truth.
- No fake data in production mode.
- Synthetic data may exist only in explicit demo/test fixtures.
- Every external record has provenance and timestamps.
- Every risk score has a scoring/model version.
- Every material state change is auditable.
- No silent mock fallback after upstream failure.
- Core platform functionality must not require paid AI APIs.
- Security is defensive only; no unauthorized exploitation.
- Every feature requires tests and verification.

## 4. Target Architecture

```text
React/TypeScript
      |
 HTTPS + WebSocket/SSE
      |
 FastAPI
      |
 +-- Auth/RBAC/Organizations
 +-- Vulnerabilities/Assets/Findings
 +-- Risk/Analytics/Remediation
 +-- Reports/Audit/Notifications
 +-- Integrations
      |
 PostgreSQL <---- Redis/event transport
      |
 Workers + Scheduler
      |
 +-- NVD
 +-- EPSS
 +-- CISA KEV
 +-- OSV
 +-- GitHub Advisory
 +-- CSAF
 +-- SBOM/Trivy/Grype/Syft
 +-- Wazuh/OpenVAS/etc.
      |
 Risk recalculation -> Event -> UI/Alerts
```

Use a modular monolith with worker processes first. Do not introduce microservices only for architectural fashion.

## 5. Phased Implementation

### Phase 0 - Stabilize

- Establish canonical repository docs.
- Separate demo/research assets from production code.
- Pin dependencies.
- Define `.env.example`.
- Add standard developer commands.

**Done when:** clean install, tests and build pass reproducibly.

### Phase 1 - Backend Source of Truth

- Replace simulated route behavior with PostgreSQL queries/writes.
- Add repository/service layers.
- Add migrations.
- Add pagination/filtering/sorting.
- Remove browser-side authoritative scoring.

**Done when:** all production APIs are backed by persisted records.

### Phase 2 - Vulnerability Intelligence

Priority connectors:

1. NVD
2. EPSS
3. CISA KEV
4. OSV
5. GitHub Advisory
6. CSAF

Implement common connector lifecycle:

```text
validate -> fetch -> normalize -> validate records -> persist -> checkpoint -> emit events
```

Every connector must support timeout, retry, rate limiting, checkpointing, deduplication and health reporting.

### Phase 3 - Asset and Finding Ingestion

First supported real path:

```text
CycloneDX/SPDX -> component normalization -> asset association -> findings -> CVE mapping
```

Preferred scanner integration order:

1. Trivy
2. Syft/Grype
3. Wazuh
4. OpenVAS/Greenbone Community Edition

### Phase 4 - Deterministic Risk Engine

Server-side features:

- CVSS
- EPSS
- KEV
- exploit availability
- threat activity
- asset criticality
- internet exposure
- business impact
- vulnerability age

Persist:

- score;
- priority P0-P3;
- contributing factors;
- evidence references;
- scoring policy version;
- trigger event;
- historical score changes.

### Phase 5 - ML

Benchmarks:

- CVSS-only
- CVSS + EPSS
- CVSS + EPSS + KEV
- deterministic contextual risk
- ML candidates: Logistic Regression, Random Forest/Gradient Boosting, XGBoost/LightGBM

Requirements:

- time-aware splits;
- label provenance;
- no target leakage;
- dataset versioning;
- ROC-AUC, PR-AUC, F1, Precision@K, Recall@K, ranking metrics;
- SHAP explanations;
- model version and checksum tracking.

### Phase 6 - Realtime

Add Redis/event transport and typed domain events:

- `vulnerability.updated`
- `epss.updated`
- `kev.changed`
- `asset.changed`
- `exposure.changed`
- `finding.created`
- `finding.updated`
- `risk.changed`
- `remediation.changed`
- `integration.sync_failed`

Connected users must see important changes without a browser refresh.

### Phase 7 - Identity, RBAC and Multi-Tenancy

Minimum roles:

- Platform Admin
- Security Admin
- Vulnerability Manager
- SOC Analyst
- Asset Owner
- Remediation Engineer
- Auditor
- Read Only

All tenant-owned queries must be organization-scoped server-side.

### Phase 8 - Remediation

Lifecycle:

```text
Open -> Acknowledged -> In Progress -> Patch Scheduled -> Patch Applied
     -> Verification Pending -> Remediated
```

Separate states for:

- False Positive
- Accepted Risk
- Mitigated / Compensating Control

Require evidence and audit history.

### Phase 9 - Analytics, Alerts and Reports

Dashboard metrics must come from persisted data:

- total vulnerabilities;
- P0/P1/P2/P3 distribution;
- top-risk assets;
- CVSS vs EPSS;
- KEV exposure;
- vulnerability aging;
- patch backlog;
- risk trend;
- team/department risk;
- risk reduction after remediation;
- SLA performance.

### Phase 10 - Hardening

- health/readiness/liveness;
- backups and restore;
- container health checks;
- integration tests;
- performance tests;
- dependency scanning;
- secret detection;
- migration tests;
- CI gates.

### Phase 11 - Open-Source Release

Add:

- `README.md`
- `DEVELOPMENT.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- architecture docs
- threat model
- API docs
- connector guides
- demo mode guide
- release process

## 6. Target Domain Model

Core entities:

```text
organization
user
role
membership
asset
software_component
asset_component
vulnerability
vulnerability_reference
epss_observation
kev_observation
exploit_signal
finding
risk_score
risk_score_history
risk_factor
remediation_task
remediation_event
integration
sync_job
sync_checkpoint
alert
notification
audit_log
model_registry
```

### Historical integrity

Store `observed_at` and `retrieved_at` separately. Do not destructively overwrite intelligence history when trends or evidence matter.

## 7. API Contract

Representative routes:

```text
POST /auth/login
POST /auth/refresh
POST /auth/logout
GET  /assets
POST /assets
PATCH /assets/{id}
GET  /vulnerabilities
GET  /vulnerabilities/{cve}
GET  /findings
GET  /findings/{id}
GET  /risk/top
GET  /risk/{finding_id}
GET  /risk/{finding_id}/history
POST /remediation
PATCH /remediation/{id}
GET  /integrations
POST /integrations
POST /integrations/{id}/sync
GET  /analytics/overview
GET  /analytics/trend
POST /reports
GET  /reports/{id}
GET  /audit
GET  /health/live
GET  /health/ready
GET  /health/integrations
```

## 8. Frontend Conversion

Production mode must stop importing demo data.

Replace:

```text
React -> demoData.ts -> browser scoring
```

with:

```text
React -> API client -> FastAPI -> PostgreSQL/risk engine
                           |
                       realtime events
```

Add explicit states for:

- loading;
- stale;
- degraded;
- unavailable;
- synchronization in progress.

If the backend cannot produce an authoritative score, display `Unavailable` and the reason. Do not fabricate a number.

## 9. Testing Gates

Every phase needs relevant automated tests.

Minimum layers:

- unit;
- API;
- database integration;
- connector integration;
- ML evaluation;
- browser/E2E;
- security regression;
- migration;
- performance;
- recovery.

A feature is not done until the implementation, tests, API/UI integration, failure handling and documentation are complete.

## 10. Docker/Deployment

Required baseline deployment:

```text
frontend
api
worker
scheduler
postgres
redis
```

Target command:

```bash
docker compose up -d
```

Optional connectors may use Compose profiles.

## 11. Production Readiness Checklist

- [ ] No production dependency on `src/data/demoData.ts`.
- [ ] No simulated production endpoints.
- [ ] PostgreSQL is authoritative.
- [ ] NVD/EPSS/KEV sync is scheduled and observable.
- [ ] At least one real SBOM/scanner path creates findings.
- [ ] Finding -> asset -> CVE mapping works.
- [ ] Risk score is server-calculated and stored.
- [ ] Risk history exists.
- [ ] Explanations include evidence and versioning.
- [ ] Realtime risk updates work without refresh.
- [ ] Authentication/RBAC/tenant isolation work.
- [ ] Remediation workflow is persistent and verifiable.
- [ ] Reports/alerts use real data.
- [ ] Docker Compose starts the complete stack.
- [ ] CI runs tests/security/build checks.
- [ ] Demo mode is isolated and labelled.

## 12. AI Agent Milestone Rule

The agent must work in vertical slices. For each milestone:

1. inspect the current repository;
2. implement only the required architectural slice;
3. add/update migrations;
4. add tests;
5. wire API to frontend if applicable;
6. run the relevant verification suite;
7. document changed files and known limitations;
8. do not claim production readiness until the acceptance gate is demonstrably passing.
