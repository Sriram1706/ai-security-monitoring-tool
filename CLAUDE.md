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

## Vulnerabilities Found (Not Yet Fixed)

### Python Code — Bandit (SAST)
- `backend/app/config.py:3` — Hardcoded SECRET_KEY
- `backend/app/routes/security.py:253` — URL open (file:/ scheme risk)
- `backend/app/services/threat_intel.py:88` — URL open (file:/ scheme risk)
- `backend/app/sqlite_store.py:410` — Potential SQL injection
- `backend/app/sqlite_store.py:555` — Potential SQL injection

### Python Dependencies — pip-audit (SCA)
- `python-jose` 3.3.0 → fix: 3.4.0+ (2 CVEs)
- `python-multipart` 0.0.9 → fix: 0.0.26+ (3 CVEs)
- `starlette` 0.38.6 → fix: 0.47.2+ (2 CVEs)
- `python-dotenv` 1.2.1 → fix: 1.2.2+ (1 CVE)

### Frontend — npm audit (SCA)
- `lodash` — High: code injection + prototype pollution
- `axios` — Moderate: SSRF
- `postcss` — Moderate: XSS
- `follow-redirects` — Moderate: auth header leak
- `esbuild` — Moderate: dev server CSRF

## Next Steps (In Priority Order)
1. ⚠️ Regenerate OpenAI API keys at platform.openai.com/api-keys
2. Add GitHub Secrets (SNYK_TOKEN, SEMGREP_APP_TOKEN, OPENAI_API_KEY)
3. Fix vulnerabilities — merge Dependabot PRs + fix Bandit findings in code
4. Set up branch protection — require CI to pass before merging to main
5. Deploy the app — pick cloud target (AWS, Render, Railway, etc.)

## How to Resume
When starting a new Claude session inside this directory, Claude will read this file automatically. Just say:
> "Continue where we left off on the AI security monitoring tool"
