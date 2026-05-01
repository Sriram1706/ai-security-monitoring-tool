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

## ECS Deployment via Terraform (Added 2026-05-01)
Full pipeline: Code Push → CI Security Checks → Auto-Deploy to AWS ECS (EC2 t2.micro, free tier)

### Files Created
- `deploy/terraform/` — full Terraform IaC (ECR, IAM, ECS cluster, EC2, CloudWatch logs)
- `deploy/ecs/task-definition.json` — ECS task definition template (used by deploy-ecs.yml)
- `frontend/nginx.ecs.conf` — ECS nginx config (proxies `/api/` to `localhost:8000`, not `backend:8000`)
- `frontend/Dockerfile` — now accepts `--build-arg NGINX_CONF=nginx.ecs.conf`
- `.github/workflows/terraform.yml` — Terraform plan on PRs, apply on push to main
- `.github/workflows/deploy-ecs.yml` — deploy workflow (auto-triggers after CI passes on main)

### How the Deploy Pipeline Works
1. Push to `main` → `ci.yml` runs all security checks
2. CI passes → `deploy-ecs.yml` auto-triggers via `workflow_run`
3. Builds backend + frontend Docker images → pushes to ECR
4. Registers new ECS task definition revision
5. Updates ECS service → waits for `services-stable`
6. Prints deployed URL: `http://<EC2-public-IP>`

### Terraform State — Terraform Cloud (Free)
1. Sign up at https://app.terraform.io (free)
2. Create an organization (e.g. `sriram-devops`)
3. Replace `YOUR_TF_ORG_HERE` in `deploy/terraform/main.tf` with your org name
4. Create API token: User Settings → Tokens → Create an API token
5. Add as GitHub secret: `TF_API_TOKEN`

### GitHub Secrets to Add (Terraform + ECS)
Add at: github.com/Sriram1706/ai-security-monitoring-tool/settings/secrets/actions
- `TF_API_TOKEN` — Terraform Cloud API token (from Step 4 above)
- `AWS_ACCESS_KEY_ID` — root/admin AWS key (for Terraform to provision infra)
- `AWS_SECRET_ACCESS_KEY` — root/admin AWS secret
- `AWS_REGION` — e.g. `us-east-1`
- `DB_PASSWORD` — Postgres password (e.g. `ChangeMe123!`)
- `JWT_SECRET` — run `openssl rand -hex 32` and paste result

After first `terraform apply`, update the two AWS secrets with the narrower `github-deployer` keys output by Terraform.

### No Manual AWS Console Steps Needed
All AWS resources (ECR, IAM, ECS cluster, EC2, CloudWatch) are provisioned automatically by `terraform apply` when you push to `deploy/terraform/**`.

### ECS Architecture Notes
- Network mode: `host` — all containers share EC2 network namespace, talk via `localhost`
- No ALB — EC2 public IP exposed directly on port 80 (saves ~$16/month, free tier)
- Postgres data persists at `/data/pgdata` on the EC2 host volume
- CloudWatch Logs stream: `/ecs/ai-security-monitoring/backend`, `.../db`, `.../frontend`

## Next Steps (In Priority Order)
1. Complete AWS one-time setup (see above) and add GitHub secrets
2. Enable GitHub Pages (settings/pages → gh-pages branch)
3. Fix `routes/security.py:253` — URL open Bandit finding
4. Merge Dependabot PRs — 13 open PRs fixing frontend/backend CVEs
5. Set up branch protection — require CI to pass before merging to main
6. Add SNYK_TOKEN secret for full Snyk reporting in Security tab

## How to Resume
When starting a new Claude session inside this directory, Claude will read this file automatically. Just say:
> "Continue where we left off on the AI security monitoring tool"
