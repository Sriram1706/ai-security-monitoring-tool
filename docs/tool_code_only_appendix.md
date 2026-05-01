# Tool Code-Only Appendix

## Backend - Code Inventory
```text
backend/app/main.py
backend/app/auth.py
backend/app/config.py
backend/app/database.py
backend/app/metrics.py
backend/app/middleware.py
backend/app/models.py
backend/app/schemas.py
backend/app/sqlite_store.py
backend/app/routes/auth.py
backend/app/routes/security.py
backend/app/risk/atlas.py
backend/app/risk/compliance.py
backend/app/risk/detector.py
backend/app/risk/framework.py
backend/app/risk/policy.py
backend/app/risk/prompt_injection_guard.py
backend/app/risk/scoring.py
backend/app/services/alerts.py
backend/app/services/audit.py
backend/app/services/code_security_scanner.py
backend/app/services/llm_provider.py
backend/app/services/supply_chain_scanner.py
backend/app/services/threat_intel.py
```

## Backend - Route Declarations
```text
POST /auth/register
POST /auth/login
GET  /auth/me

POST /scan
POST /process-prompt
GET  /gateway/sources
POST /gateway/sources
POST /gateway/sources/{source_id}/rotate-key
POST /gateway/sources/{source_id}/disable
POST /gateway/sources/{source_id}/enable
GET  /policy/control-plane
POST /gateway/evaluate
POST /gateway/process
POST /scan-url
POST /mirror/chatgpt
POST /mirror/cursor
GET  /threat-intel/status
GET  /alerts
GET  /logs
GET  /code-findings
GET  /code-findings/summary
POST /logs/{log_id}/action
GET  /analytics
GET  /threat-summary
GET  /supply-chain
GET  /aidr/incidents
GET  /aidr/attack-path
GET  /admin/audit-chain/verify
POST /admin/seed-sample-scans
POST /admin/reclassify-logs
```

## Backend - SQLite Tables
```sql
logs
code_findings
connector_sources
threat_intel_rules
```

## Frontend - Code Inventory
```text
frontend/src/App.jsx
frontend/src/main.jsx
frontend/src/index.css
frontend/src/lib/api.js
frontend/src/lib/apiFetch.js
frontend/src/lib/threatExplain.js
frontend/src/lib/timeRange.js

frontend/src/pages/Dashboard.jsx
frontend/src/pages/Requests.jsx
frontend/src/pages/Integrations.jsx
frontend/src/pages/SupplyChain.jsx
frontend/src/pages/Posture.jsx
frontend/src/pages/AIFirewall.jsx
frontend/src/pages/AgenticRisks.jsx
frontend/src/pages/Reports.jsx
frontend/src/pages/Visibility.jsx
frontend/src/pages/Risks.jsx
frontend/src/pages/Settings.jsx
frontend/src/pages/Threats.jsx

frontend/src/components/ActionPanel.jsx
frontend/src/components/AdvancedAnalyticsPanel.jsx
frontend/src/components/AlertsPanel.jsx
frontend/src/components/AttackTimeline.jsx
frontend/src/components/DrilldownDrawer.jsx
frontend/src/components/DrilldownPanel.jsx
frontend/src/components/FiltersBar.jsx
frontend/src/components/HeroThreatPanel.jsx
frontend/src/components/InsightsPanel.jsx
frontend/src/components/LogsTable.jsx
frontend/src/components/PrimaryInsightBanner.jsx
frontend/src/components/PromptConsole.jsx
frontend/src/components/RiskCharts.jsx
frontend/src/components/RiskCorrelationView.jsx
frontend/src/components/SecurityScorePanel.jsx
frontend/src/components/SecurityScoreTrendline.jsx
frontend/src/components/SeverityBadge.jsx
frontend/src/components/SidebarNav.jsx
frontend/src/components/SocAlertsPanel.jsx
frontend/src/components/ThreatAnalysisPanel.jsx
frontend/src/components/ThreatDetailModal.jsx
frontend/src/components/ThreatIntelPanel.jsx
frontend/src/components/TopThreatCard.jsx
```

## Frontend - Active Sidebar Routes
```text
/dashboard
/requests
/integrations
/supply-chain
/posture
/ai-firewall
/agentic-risks
/reports
```

## Frontend - Additional Routes In App
```text
/visibility
/risks
/vulnerability-findings -> redirect /supply-chain
```

## Ops / Scripts - Code Inventory
```text
deploy/docker-compose.yml
deploy/prometheus.yml
deploy/backup.sh
deploy/backup.sql
deploy/backup_safe.sql

scripts/backup_security_db.sh
scripts/restore_security_db.sh
scripts/list_security_backups.sh
scripts/daily_backup_runner.sh
scripts/install_daily_backup_launchd.sh
scripts/status_daily_backup_launchd.sh
scripts/uninstall_daily_backup_launchd.sh
scripts/ide_local_helper.py
scripts/cursor_demo_mirror.py
```
