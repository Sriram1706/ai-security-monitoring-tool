# AI Security Monitoring Tool — Project Context

## Project
- **App location:** `/Users/snarayanan/Documents/AI Security/ai_security_monitoring_tool`
- **GitHub repo:** https://github.com/Sriram1706/ai-security-monitoring-tool (PUBLIC)
- **GitHub user:** Sriram1706
- **Stack:** Python/FastAPI backend + React/Vite frontend + Docker Compose + PostgreSQL + Prometheus + Grafana

## What Has Been Done
- `.gitignore` created — blocks `.env`, `security.db`, `backups/`, `logs/`, secrets
- Code pushed to GitHub (136 files, no secrets leaked)
- Repo made public (unlocks free GitHub Advanced Security)
- Secret scanning + push protection enabled
- Dependabot configured — auto-created 23 PRs fixing outdated packages
- Full CI/CD security pipeline created at `.github/workflows/ci.yml`

## Security Pipeline
| Tool | Type | Notes |
|---|---|---|
| Semgrep | SAST | OWASP Top 10, secrets, React, Docker rulesets |
| CodeQL | SAST | Python + JavaScript deep analysis |
| Snyk | SCA | Needs `SNYK_TOKEN` GitHub secret |
| Trivy | SCA | Filesystem + Docker image CVE scan |
| Dependabot | SCA | Weekly auto-PRs — already active |
| Checkov | IaC | Dockerfile + docker-compose misconfig scan |
| OWASP ZAP | DAST | Needs `OPENAI_API_KEY` GitHub secret to run app |
| Gitleaks | Secrets | Scans full git history |

## GitHub Secrets Needed (Not Yet Added)
Add at: github.com/Sriram1706/ai-security-monitoring-tool/settings/secrets/actions
- `SNYK_TOKEN` — get from app.snyk.io → Account Settings → Auth Token
- `SEMGREP_APP_TOKEN` — get from semgrep.dev → Settings → Tokens (optional)
- `OPENAI_API_KEY` — regenerate at platform.openai.com/api-keys (old key was exposed)

## CI Pipeline Status
All jobs green as of May 1, 2026:
Semgrep ✅ | CodeQL ✅ | Trivy ✅ | Snyk ✅ | Checkov ✅ | Gitleaks ✅ | ZAP ✅ | Dashboard Deploy ✅

## Vulnerabilities Fixed
- `backend/app/config.py` — hardcoded SECRET_KEY replaced with `secrets.token_hex(32)`
- `backend/app/services/threat_intel.py` — URL scheme validation (http/https only)
- `backend/app/sqlite_store.py` — nosec B608 annotations with allowlist justification
- `backend/requirements.txt` — python-jose→3.5.0, python-multipart→0.0.27, fastapi→0.136.1, python-dotenv→1.2.2
- `frontend/package.json` — vite 5→8, @vitejs/plugin-react 4→6
- `frontend/nginx.conf` — `$host` → `$server_name`

## Still Open
- `backend/app/routes/security.py:253` — URL open (same fix as threat_intel.py)
- Frontend CVEs (lodash, axios, postcss, follow-redirects) — Dependabot PRs open, ready to merge

## Live Security Dashboard
- Auto-deploys to GitHub Pages after every CI run
- Enable at: github.com/Sriram1706/ai-security-monitoring-tool/settings/pages → gh-pages branch
- URL: https://sriram1706.github.io/ai-security-monitoring-tool/

## Next Steps (In Priority Order)
1. Enable GitHub Pages (settings/pages → gh-pages branch)
2. Fix `routes/security.py:253` — URL open Bandit finding
3. Merge Dependabot PRs — 13 open PRs fixing frontend/backend CVEs
4. Set up branch protection — require CI to pass before merging to main
5. Add SNYK_TOKEN secret for full Snyk reporting in Security tab
6. Deploy the app — pick cloud target (AWS, Render, Railway, etc.)

## How to Resume
When starting a new Claude session inside this directory, Claude will read this file automatically. Just say:
> "Continue where we left off on the AI security monitoring tool"
