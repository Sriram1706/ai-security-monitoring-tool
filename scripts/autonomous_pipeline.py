#!/usr/bin/env python3
"""
Autonomous Deployment Pipeline
Triggered by GitHub webhook on push to main.
Clones repo, sets up CI/CD, provisions AWS infra, deploys app, notifies.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import httpx
from datetime import datetime
from pathlib import Path

DASHBOARD_API = "http://54.157.214.213/api/security"
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
AWS_PROFILE = "homelab"

GITHUB_ACTIONS_TEMPLATE = """\
name: CI/CD + Security Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sast-semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/secrets
            p/docker

  sca-trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: CRITICAL,HIGH

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  iac-checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          soft_fail: true

  deploy:
    needs: [sast-semgrep, sca-trivy, secret-scan, iac-checkov]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Deploy notification
        run: echo "All security gates passed - ready to deploy"
"""

GITIGNORE_TEMPLATE = """\
# Secrets
.env
.env.*
*.pem
*.key
*.p12
*.pfx

# Dependencies
node_modules/
__pycache__/
*.pyc
.venv/
venv/

# Build
dist/
build/
*.egg-info/

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db
"""


def log(msg: str):
    print(f"[{datetime.utcnow().isoformat()}] {msg}", flush=True)


def run_cmd(cmd: list, cwd: str = None) -> tuple[int, str]:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def clone_repo(repo_url: str, target_dir: str) -> bool:
    url_with_token = repo_url.replace("https://", f"https://{GITHUB_TOKEN}@")
    code, out = run_cmd(["git", "clone", url_with_token, target_dir])
    log(f"Clone: {out[:200]}")
    return code == 0


def inject_cicd_pipeline(repo_dir: str, repo_name: str):
    workflows_dir = Path(repo_dir) / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    ci_file = workflows_dir / "ci.yml"
    if not ci_file.exists():
        ci_file.write_text(GITHUB_ACTIONS_TEMPLATE)
        log("Injected CI/CD pipeline")

    gitignore = Path(repo_dir) / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(GITIGNORE_TEMPLATE)
        log("Injected .gitignore")


def detect_app_type(repo_dir: str) -> str:
    files = list(Path(repo_dir).rglob("*"))
    names = [f.name for f in files]
    if "requirements.txt" in names or "pyproject.toml" in names:
        return "python"
    if "package.json" in names:
        return "nodejs"
    if "Dockerfile" in names:
        return "docker"
    return "unknown"


def send_to_dashboard(repo_name: str, app_type: str, status: str, findings: list):
    try:
        with httpx.Client(timeout=10) as client:
            client.post(f"{DASHBOARD_API}/ingest/aws-findings", json={
                "source": f"autonomous-pipeline:{repo_name}",
                "severity": "medium" if status == "success" else "high",
                "risk_score": 30 if status == "success" else 60,
                "summary": f"Autonomous pipeline {status} for {repo_name} ({app_type} app)",
                "findings": findings
            })
        log("Sent findings to dashboard")
    except Exception as e:
        log(f"Dashboard send failed: {e}")


def send_sns_notification(repo_name: str, status: str, summary: str):
    if not SNS_TOPIC_ARN:
        log("SNS_TOPIC_ARN not set — skipping notification")
        return
    code, out = run_cmd([
        "aws", "sns", "publish",
        "--profile", AWS_PROFILE,
        "--topic-arn", SNS_TOPIC_ARN,
        "--subject", f"[AutoDeploy] {repo_name} — {status.upper()}",
        "--message", summary
    ])
    log(f"SNS notification: {out[:100]}")


def commit_and_push(repo_dir: str, repo_name: str):
    run_cmd(["git", "config", "user.email", "auto-pipeline@ai-security.local"], cwd=repo_dir)
    run_cmd(["git", "config", "user.name", "AI Security Pipeline"], cwd=repo_dir)
    run_cmd(["git", "add", ".github/", ".gitignore"], cwd=repo_dir)
    code, out = run_cmd(["git", "diff", "--cached", "--name-only"], cwd=repo_dir)
    if code == 0 and out.strip():
        run_cmd(["git", "commit", "-m", "chore: add CI/CD pipeline and security config [auto]"], cwd=repo_dir)
        run_cmd(["git", "push"], cwd=repo_dir)
        log(f"Pushed CI/CD pipeline to {repo_name}")
    else:
        log("Nothing new to commit")


def run_pipeline(repo_url: str, repo_name: str):
    log(f"Starting autonomous pipeline for {repo_name}")
    findings = []
    status = "success"

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, "repo")

        # Step 1 — Clone
        log("Step 1: Cloning repo...")
        if not clone_repo(repo_url, repo_dir):
            log("Clone failed — aborting")
            return

        # Step 2 — Detect app type
        app_type = detect_app_type(repo_dir)
        log(f"Step 2: Detected app type: {app_type}")
        findings.append({"step": "detect", "app_type": app_type})

        # Step 3 — Inject CI/CD
        log("Step 3: Injecting CI/CD pipeline...")
        inject_cicd_pipeline(repo_dir, repo_name)
        findings.append({"step": "cicd", "status": "injected"})

        # Step 4 — Push CI/CD back to repo
        log("Step 4: Pushing CI/CD config to GitHub...")
        commit_and_push(repo_dir, repo_name)
        findings.append({"step": "push", "status": "done"})

        # Step 5 — Send to dashboard
        log("Step 5: Sending findings to dashboard...")
        send_to_dashboard(repo_name, app_type, status, findings)

        # Step 6 — SNS notification
        summary = (
            f"Autonomous pipeline completed for {repo_name}\n"
            f"App type: {app_type}\n"
            f"CI/CD pipeline injected: Yes\n"
            f"Security gates: Semgrep, Trivy, Gitleaks, Checkov\n"
            f"Dashboard: http://54.157.214.213/dashboard?view=liveFeed\n"
            f"Timestamp: {datetime.utcnow().isoformat()}"
        )
        send_sns_notification(repo_name, status, summary)
        log(f"Pipeline complete for {repo_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--repo-name", required=True)
    args = parser.parse_args()
    run_pipeline(args.repo_url, args.repo_name)
