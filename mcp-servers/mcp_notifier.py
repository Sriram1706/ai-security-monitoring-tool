import boto3
import json
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Notifier")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
AWS_PROFILE = "homelab"


def get_sns():
    return boto3.Session(profile_name=AWS_PROFILE).client("sns", region_name="us-east-1")


@mcp.tool()
def create_sns_topic(topic_name: str = "ai-security-alerts") -> str:
    """Create an SNS topic for security alerts and pipeline notifications."""
    try:
        sns = get_sns()
        response = sns.create_topic(Name=topic_name)
        arn = response["TopicArn"]
        return json.dumps({"topic_arn": arn, "status": "created"}, indent=2)
    except Exception as e:
        return f"Failed to create SNS topic: {str(e)}"


@mcp.tool()
def subscribe_email(topic_arn: str, email: str) -> str:
    """Subscribe an email address to receive security alerts."""
    try:
        sns = get_sns()
        response = sns.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint=email
        )
        return json.dumps({
            "subscription_arn": response["SubscriptionArn"],
            "status": "pending_confirmation",
            "message": f"Confirmation email sent to {email}"
        }, indent=2)
    except Exception as e:
        return f"Subscription failed: {str(e)}"


@mcp.tool()
def send_security_alert(topic_arn: str, subject: str, message: str) -> str:
    """Send a security alert notification via SNS."""
    try:
        sns = get_sns()
        sns.publish(
            TopicArn=topic_arn,
            Subject=f"[AI Security] {subject}",
            Message=message
        )
        return json.dumps({"status": "sent", "subject": subject}, indent=2)
    except Exception as e:
        return f"Failed to send alert: {str(e)}"


@mcp.tool()
def send_pipeline_summary(topic_arn: str, repo_name: str, status: str, findings_count: int, dashboard_url: str = "http://54.157.214.213/dashboard?view=liveFeed") -> str:
    """Send autonomous pipeline completion summary via SNS."""
    try:
        sns = get_sns()
        message = f"""
Autonomous Pipeline Report
==========================
Repository : {repo_name}
Status     : {status.upper()}
Findings   : {findings_count}
Dashboard  : {dashboard_url}
Timestamp  : {__import__('datetime').datetime.utcnow().isoformat()}

Security gates run:
- SAST: Semgrep + CodeQL
- SCA: Trivy + Snyk
- Secrets: Gitleaks
- IaC: Checkov
- DAST: OWASP ZAP

View full report at: {dashboard_url}
        """.strip()

        sns.publish(
            TopicArn=topic_arn,
            Subject=f"[AutoDeploy] {repo_name} — {status.upper()}",
            Message=message
        )
        return json.dumps({"status": "sent", "repo": repo_name}, indent=2)
    except Exception as e:
        return f"Failed to send summary: {str(e)}"


@mcp.tool()
def list_topics() -> str:
    """List all SNS topics in the homelab account."""
    try:
        sns = get_sns()
        topics = sns.list_topics()["Topics"]
        return json.dumps([t["TopicArn"] for t in topics], indent=2)
    except Exception as e:
        return f"Failed to list topics: {str(e)}"


if __name__ == "__main__":
    mcp.run()
