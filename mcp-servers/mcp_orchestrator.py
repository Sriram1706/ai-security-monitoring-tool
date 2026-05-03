import sys
import json
import httpx
from datetime import datetime
from github import Auth, Github, GithubException
from mcp.server.fastmcp import FastMCP
import boto3

sys.path.insert(0, "mcp-servers")
from mcp_security_middleware import secure_tool_call, get_audit_log

API_BASE = "http://54.157.214.213"
REPO_NAME = "Sriram1706/ai-security-monitoring-tool"

import os
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

mcp = FastMCP("Security Orchestrator")


def _scan_content(content: str) -> dict:
    try:
        with httpx.Client(timeout=30) as client:
            r = client.post(f"{API_BASE}/api/security/scan", json={"content": content, "source": "orchestrator"})
            return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _lookup_cve(cve_id: str) -> dict:
    try:
        with httpx.Client(timeout=30) as client:
            r = client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve_id})
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0]["cve"]
                    metrics = cve.get("metrics", {})
                    cvss = (
                        metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                        or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                        or {}
                    )
                    return {
                        "score": cvss.get("baseScore", "N/A"),
                        "severity": cvss.get("baseSeverity", "UNKNOWN"),
                        "description": next(
                            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                            "No description"
                        )[:300]
                    }
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _create_github_issue(title: str, body: str) -> str:
    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        issue = repo.create_issue(title=f"[SECURITY] {title}", body=body, labels=["security"])
        return issue.html_url
    except GithubException as e:
        return f"Failed: {e.data}"


def _audit_aws() -> dict:
    report = {}
    try:
        ec2 = boto3.client("ec2", region_name="us-east-1")
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        open_sgs = [
            sg["GroupId"] for sg in sgs
            for rule in sg.get("IpPermissions", [])
            for ip in rule.get("IpRanges", [])
            if ip.get("CidrIp") == "0.0.0.0/0"
        ]
        report["security_groups"] = {"open_to_internet": open_sgs}
    except Exception as e:
        report["security_groups"] = {"error": str(e)}
    try:
        iam = boto3.client("iam", region_name="us-east-1")
        users = iam.list_users()["Users"]
        risky = []
        for u in users:
            mfa = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
            keys = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
            if not mfa and keys:
                risky.append(u["UserName"])
        report["iam"] = {"users_without_mfa": risky}
    except Exception as e:
        report["iam"] = {"error": str(e)}
    return report


@mcp.tool()
@secure_tool_call("orchestrator", "full_security_pipeline")
def full_security_pipeline(content: str, create_issues: bool = True) -> str:
    """
    Run the full autonomous security pipeline:
    1. Scan content for threats
    2. Enrich findings with CVE data
    3. Audit AWS infrastructure
    4. Auto-create GitHub issues for high/critical findings
    5. Return consolidated report
    """
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "pipeline": "full_security_pipeline",
        "stages": {}
    }

    # Stage 1 — Scan content
    print("Stage 1: Scanning content...")
    scan_result = _scan_content(content)
    report["stages"]["scan"] = scan_result
    findings = scan_result.get("findings", [])
    risk_score = scan_result.get("risk_score", 0)
    severity = scan_result.get("severity", "low")

    # Stage 2 — CVE enrichment for any CVE IDs in findings
    print("Stage 2: CVE enrichment...")
    cve_data = {}
    for finding in findings:
        desc = str(finding.get("description", ""))
        import re
        cve_ids = re.findall(r"CVE-\d{4}-\d+", desc)
        for cve_id in cve_ids:
            cve_data[cve_id] = _lookup_cve(cve_id)
    report["stages"]["cve_enrichment"] = cve_data if cve_data else "No CVE IDs found in findings"

    # Stage 3 — AWS audit
    print("Stage 3: AWS infrastructure audit...")
    aws_report = _audit_aws()
    report["stages"]["aws_audit"] = aws_report

    # Stage 4 — Auto-create GitHub issues for high/critical findings
    issues_created = []
    if create_issues and severity in ("high", "critical") and GITHUB_TOKEN:
        print("Stage 4: Creating GitHub issues...")
        aws_findings = []
        open_sgs = aws_report.get("security_groups", {}).get("open_to_internet", [])
        risky_iam = aws_report.get("iam", {}).get("users_without_mfa", [])
        if open_sgs:
            aws_findings.append(f"Security groups open to internet: {', '.join(open_sgs)}")
        if risky_iam:
            aws_findings.append(f"IAM users without MFA: {', '.join(risky_iam)}")

        issue_body = f"""## Automated Security Scan Report
**Timestamp:** {report['timestamp']}
**Risk Score:** {risk_score}
**Severity:** {severity.upper()}

## Scan Findings
```json
{json.dumps(findings, indent=2)}
```

## CVE Data
```json
{json.dumps(cve_data, indent=2)}
```

## AWS Infrastructure Findings
{chr(10).join(f'- {f}' for f in aws_findings) if aws_findings else '- No critical AWS findings'}

---
*Auto-generated by MCP Security Orchestrator*
"""
        url = _create_github_issue(
            f"Security scan found {severity.upper()} risk (score: {risk_score})",
            issue_body
        )
        issues_created.append(url)

    report["stages"]["github_issues"] = issues_created if issues_created else "No issues created (severity below threshold or create_issues=False)"

    # Final summary
    report["summary"] = {
        "risk_score": risk_score,
        "severity": severity,
        "findings_count": len(findings),
        "cves_found": len(cve_data),
        "aws_open_sgs": len(aws_report.get("security_groups", {}).get("open_to_internet", [])),
        "github_issues_created": len(issues_created)
    }

    return json.dumps(report, indent=2)


@mcp.tool()
@secure_tool_call("orchestrator", "scan_and_report")
def scan_and_report(content: str) -> str:
    """Scan content and return a plain-English security report without creating GitHub issues."""
    scan_result = _scan_content(content)
    risk_score = scan_result.get("risk_score", 0)
    severity = scan_result.get("severity", "low")
    findings = scan_result.get("findings", [])

    if risk_score == 0:
        return f"Content is clean. No threats detected."

    lines = [
        f"Security Scan Report",
        f"Risk Score: {risk_score}/100 | Severity: {severity.upper()}",
        f"Findings ({len(findings)}):"
    ]
    for f in findings:
        lines.append(f"  - {f.get('type', 'Unknown')}: {f.get('description', '')[:100]}")

    return "\n".join(lines)


@mcp.tool()
@secure_tool_call("orchestrator", "get_audit_trail")
def get_audit_trail(lines: int = 20) -> str:
    """Get the audit trail of all MCP tool calls — who called what and when."""
    logs = get_audit_log(lines)
    return json.dumps(logs, indent=2) if logs else "No audit logs found"


@mcp.tool()
@secure_tool_call("orchestrator", "pipeline_health_check")
def pipeline_health_check() -> str:
    """Check health of all components in the security pipeline."""
    health = {}

    # Check backend
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"{API_BASE}/health")
            health["backend"] = "healthy" if r.status_code == 200 else f"unhealthy (HTTP {r.status_code})"
    except Exception as e:
        health["backend"] = f"unreachable: {str(e)}"

    # Check GitHub
    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        health["github"] = f"connected ({repo.full_name})"
    except Exception as e:
        health["github"] = f"error: {str(e)}"

    # Check AWS
    try:
        sts = boto3.client("sts", region_name="us-east-1")
        identity = sts.get_caller_identity()
        health["aws"] = f"connected (account: {identity['Account']})"
    except Exception as e:
        health["aws"] = f"error: {str(e)}"

    # Check NVD API
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"resultsPerPage": 1})
            health["nvd_api"] = "healthy" if r.status_code == 200 else f"unhealthy (HTTP {r.status_code})"
    except Exception as e:
        health["nvd_api"] = f"unreachable: {str(e)}"

    all_healthy = all("healthy" in v or "connected" in v for v in health.values())
    health["overall"] = "ALL SYSTEMS GO" if all_healthy else "DEGRADED — check individual services"

    return json.dumps(health, indent=2)


if __name__ == "__main__":
    mcp.run()
