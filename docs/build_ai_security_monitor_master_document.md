# Build AI Security Monitor - Master Implementation Document

## 1) Purpose And Scope
This document is the comprehensive, from-scratch reference for what has been built so far in the AI Security Monitoring Tool and how to continue the full codebase safely.

It covers:
- Current architecture and runtime model
- Backend and frontend implementation inventory
- Active API surface
- Data model and storage behavior
- Security/risk logic implemented to date
- UX/navigation state as currently coded
- Operational and deployment assets
- Continuation roadmap for the entire codebase

This is intended to be the single source of truth for technical handoff and future build planning.

---

## 2) Current Product State (As Implemented)
### Core capabilities already built
- Prompt and response risk analysis pipeline (risk scoring + severity)
- AI threat/risk categories (prompt injection, indirect injection, jailbreak, data exfiltration, secret exposure, policy violations, etc.)
- Policy decisioning (ALLOW/WARN/BLOCK semantics)
- URL scan enforcement path
- Mirror ingestion endpoints (ChatGPT/Cursor)
- Threat intel status + signal ingestion framework
- Supply chain scanning and risk view
- Code vulnerability findings ingestion and summary
- Analyst action workflow on logs (`FLAG`, `BLOCK`)
- Audit chain verification and admin operations
- JWT auth + role-aware endpoints
- Multi-page React analyst console with live operational views

### Current sidebar/navigation (frontend)
From `frontend/src/components/SidebarNav.jsx`:
- Dashboard
- Requests
- Integrations
- Vulnerability Findings (route key still `supply-chain`)
- Posture
- AI Firewall
- Agentic AI Risks
- Reports

Note:
- `/vulnerability-findings` route currently redirects to `/supply-chain`.
- `Visibility` and `Risks` routes still exist in code but are not shown in sidebar.

---

## 3) High-Level Runtime Architecture
### Application layers
1. `Frontend` (React + Vite):
- Analyst SOC-style UI
- Calls FastAPI endpoints with token-aware `apiFetch`

2. `Backend` (FastAPI):
- Auth, policy evaluation, risk detection, scanning, analytics
- Exposes operational and admin endpoints

3. `Risk Engine` (backend/app/risk):
- Detector, scoring, policy, framework mappings, atlas mapping, compliance mapping

4. `Storage`:
- Primary operational persistence currently uses SQLite (`security.db`) through `sqlite_store.py`
- SQLAlchemy models/database wiring also exist (for auth/user and broader persistence compatibility)

5. `Ops`:
- Docker compose stack + Prometheus/Grafana assets
- Backup/restore scripts for SQLite DB

### Important state note
Legacy architecture docs reference PostgreSQL as target production architecture; active implementation currently persists major SOC telemetry in SQLite via `backend/app/sqlite_store.py`.

---

## 4) Backend Codebase Inventory
## 4.1 App entry and wiring
- `backend/app/main.py`
  - FastAPI app init
  - CORS + middleware
  - Router registration (`auth`, `security`)
  - Startup tasks (DB init, SQLite init, threat intel scheduler, admin bootstrap)
  - Health + metrics exposure

## 4.2 Auth and identity
- `backend/app/auth.py`
- `backend/app/routes/auth.py`
- `backend/app/models.py` (User model)
- `backend/app/database.py`

Implemented:
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`

## 4.3 Security and SOC endpoints
Primary router: `backend/app/routes/security.py`

Implemented endpoint groups:
- Scanning:
  - `POST /scan`
  - `POST /process-prompt`
  - `POST /gateway/evaluate`
  - `POST /gateway/process`
  - `POST /scan-url`
- Mirror ingestion:
  - `POST /mirror/chatgpt`
  - `POST /mirror/cursor`
- Policy/control plane:
  - `GET /policy/control-plane`
- Logs/findings/analytics:
  - `GET /logs`
  - `POST /logs/{log_id}/action`
  - `GET /code-findings`
  - `GET /code-findings/summary`
  - `GET /analytics`
  - `GET /threat-summary`
- Supply chain:
  - `GET /supply-chain`
- Alerts/intel:
  - `GET /alerts`
  - `GET /threat-intel/status`
- Gateway source management:
  - `GET /gateway/sources`
  - `POST /gateway/sources`
  - `POST /gateway/sources/{source_id}/rotate-key`
  - `POST /gateway/sources/{source_id}/disable`
  - `POST /gateway/sources/{source_id}/enable`
- AIDR:
  - `GET /aidr/incidents`
  - `GET /aidr/attack-path`
- Admin:
  - `GET /admin/audit-chain/verify`
  - `POST /admin/seed-sample-scans`
  - `POST /admin/reclassify-logs`

## 4.4 Risk and policy engine modules
- `backend/app/risk/detector.py` - core heuristic detection/classification and finding generation
- `backend/app/risk/scoring.py` - risk scoring and severity mapping
- `backend/app/risk/policy.py` - policy thresholds and blocked/warn decisions
- `backend/app/risk/framework.py` - framework structures/constraints
- `backend/app/risk/atlas.py` - MITRE ATLAS mapping enrichment
- `backend/app/risk/compliance.py` - compliance controls mapping
- `backend/app/risk/prompt_injection_guard.py` - defensive checks

## 4.5 Services
- `backend/app/services/alerts.py` - alert generation pipeline
- `backend/app/services/threat_intel.py` - intel feed status/scheduling
- `backend/app/services/supply_chain_scanner.py` - dependency/package risk scan logic
- `backend/app/services/code_security_scanner.py` - code finding extraction
- `backend/app/services/audit.py` - audit event writing
- `backend/app/services/llm_provider.py` - provider integration abstraction

## 4.6 SQLite operational store
- `backend/app/sqlite_store.py`

Operational tables:
- `logs`
- `code_findings`
- `connector_sources`
- `threat_intel_rules`

Supports:
- DB init and lightweight migrations
- insert/fetch/update log records
- code findings persistence and summaries
- connector source identity management
- analytics aggregation

---

## 5) Frontend Codebase Inventory
## 5.1 App shell
- `frontend/src/App.jsx`
  - Auth gate
  - Sidebar navigation
  - Route mapping
  - Shared global filter state
  - Drilldown drawer plumbing

## 5.2 Key pages currently used
- `frontend/src/pages/Dashboard.jsx` - central SOC analytics and investigation hub
- `frontend/src/pages/Requests.jsx` - request log explorer with risk metadata and filtering
- `frontend/src/pages/Integrations.jsx` - connector source/policy control actions
- `frontend/src/pages/SupplyChain.jsx` - merged vulnerability findings + supply chain dashboard
- `frontend/src/pages/Posture.jsx` - posture summary with interactive finding drilldown
- `frontend/src/pages/AIFirewall.jsx` - policy + decision telemetry + analyst action queue
- `frontend/src/pages/AgenticRisks.jsx` - OWASP agentic risk framing + mapped incidents
- `frontend/src/pages/Reports.jsx` - summary/reporting/export-friendly views

Legacy/available routes not currently in sidebar:
- `frontend/src/pages/Visibility.jsx`
- `frontend/src/pages/Risks.jsx`

## 5.3 Reusable components
High-value SOC UI modules include:
- `AlertsPanel`, `SocAlertsPanel`
- `RiskCorrelationView`, `RiskCharts`, `AttackTimeline`
- `AdvancedAnalyticsPanel`, `InsightsPanel`, `ThreatAnalysisPanel`
- `PromptConsole`, `DrilldownDrawer`
- `SeverityBadge`, `SecurityScorePanel`, `SecurityScoreTrendline`

## 5.4 Frontend data access
- `frontend/src/lib/apiFetch.js` - token-aware fetch wrapper with fallback auto-login
- `frontend/src/lib/api.js` - axios helper and token handling

---

## 6) AI Firewall (Newest Action-Oriented Capability)
Implemented in `frontend/src/pages/AIFirewall.jsx`.

Current technical features:
- Policy control-plane readout (`/policy/control-plane`)
- Decision telemetry from `/logs` (blocked/warning/allowed/risky-allowed)
- Hard block risk list and strict prompt attack list visualization
- Source/provider scoping
- Top blocked risk types
- Recent blocked requests
- Analyst action queue with prioritization (`P1/P2/P3`)
- One-click analyst actions:
  - `FLAG` via `/logs/{id}/action`
  - `BLOCK` via `/logs/{id}/action`
- Source quarantine candidates
- Burst/drift signal detection window
- Decision matrix by risk type
- Export action queue to JSON

This page is now the foundation for containment-oriented SOC workflows.

---

## 7) Data And Persistence Snapshot
Primary runtime DB file:
- `security.db` at project root

Main data streams:
- `logs`: evaluated prompts and policy outcomes
- `code_findings`: vulnerability findings and prompt/code security issues
- `connector_sources`: integration identity and policy profile metadata
- `threat_intel_rules`: threat intel derived rules

Important observed behavior:
- UI risk and vulnerability views are now largely driven from persisted SQLite data.
- Some UI sections are heuristic overlays on top of logs/findings (intended for analyst speed).

---

## 8) Deployment And Operations Assets
### Deploy folder
- `deploy/docker-compose.yml`
- `deploy/prometheus.yml`
- backup SQL assets and backup scripts

### Backup/restore scripts
Located in `/scripts`:
- `backup_security_db.sh`
- `restore_security_db.sh`
- `list_security_backups.sh`
- launchd automation scripts for daily backups

---

## 9) Known Technical Gaps / Cleanups
1. Documentation drift:
- `README.md` and `docs/architecture.md` still include older PostgreSQL-first wording while current telemetry persistence is SQLite-heavy.

2. Route/navigation drift:
- Some routes exist but are intentionally hidden from sidebar; document intended visibility policy.

3. Large frontend bundle:
- Vite reports chunk-size warnings; code-splitting and route-level lazy loading recommended.

4. Test coverage:
- Backend tests currently minimal (`test_prompt_injection_guard.py` only).
- Add route + policy + action endpoint tests.

---

## 10) Continuation Plan For Entire Codebase
This section describes how to continue development safely without regressions.

## Phase A - Stabilize And Align
- Update architecture/readme docs to match actual runtime state.
- Add API contract docs generated from current route signatures.
- Add smoke tests for:
  - auth
  - scan/log pipeline
  - `/logs/{id}/action`
  - `/policy/control-plane`
  - `/supply-chain`

## Phase B - SOC Action Depth
- AI Firewall:
  - bulk actions (multi-select block/flag)
  - SLA timers for P1/P2
  - analyst assignment and note fields
- Incident Response tab (next logical extension)

## Phase C - Policy Engineering
- Add policy simulator/replay interface:
  - evaluate historical logs against candidate thresholds
  - compare false-positive/false-negative impact before rollout

## Phase D - Detection Quality
- Add model/provider drift metrics
- Add confidence calibration monitoring
- Add explainability standardization across findings

## Phase E - Compliance And Audit Hardening
- Control mapping dashboards (NIST/SOC2/OWASP)
- Evidence locker for incident-to-control traceability
- Immutable export bundles for auditor review

## Phase F - Performance And Reliability
- Route-level lazy loading in frontend
- Caching strategy for summary endpoints
- Retry/timeout strategy hardening in supply chain + threat intel fetches

---

## 11) Suggested Ownership Map
To continue efficiently, assign clear domain ownership:
- Backend policy/detector: `backend/app/risk/*`
- Backend API contracts: `backend/app/routes/*`, `backend/app/schemas.py`
- Storage and migrations: `backend/app/sqlite_store.py`
- Frontend SOC views: `frontend/src/pages/*`
- Shared UI components/charts: `frontend/src/components/*`
- Ops and reliability: `deploy/*`, `scripts/*`
- Documentation governance: `docs/*`, `README.md`

---

## 12) Immediate Next Build Candidates (Highest ROI)
1. AI Firewall bulk analyst actions and SLA tracking
2. Incident Response workflow tab
3. Policy Simulator tab
4. Test suite expansion across critical endpoints
5. Architecture/documentation sync and API reference generation

---

## 13) Quick Reference - Current Major Routes (Frontend)
- `/dashboard`
- `/requests`
- `/integrations`
- `/supply-chain` (Vulnerability Findings dashboard)
- `/posture`
- `/ai-firewall`
- `/agentic-risks`
- `/reports`
- `/vulnerability-findings` -> redirect to `/supply-chain`

---

## 14) Closing Note
The tool is past prototype stage and already supports meaningful analyst workflows (detection -> triage -> containment actions). The next evolution should prioritize operational rigor: policy simulation, incident ownership/SLA, and stronger automated testing around enforcement actions.

---

## 15) Code-Only Appendix
For a coding-only view (no architecture narrative), see:

- `/docs/tool_code_only_appendix.md`

---

## 16) Detailed Tool Spec + Cursor Connectivity
For a deeper technical reference focused on system specification, current architecture, and end-to-end Cursor integration/connectivity, see:

- `/docs/tool_spec_architecture_cursor_connectivity.md`

---

## 17) Detailed Work History (With Diagrams)
For a complete record of the work carried out so far (frontend + backend changes, UX corrections, rollbacks, and architecture/timeline diagrams), see:

- `/docs/work_carried_out_detailed.md`
