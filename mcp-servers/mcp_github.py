import os
import json
from github import Github, GithubException
from mcp.server.fastmcp import FastMCP

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO_NAME = "Sriram1706/ai-security-monitoring-tool"

mcp = FastMCP("GitHub Integration")


def get_repo():
    g = Github(GITHUB_TOKEN)
    return g.get_repo(REPO_NAME)


@mcp.tool()
def create_security_issue(title: str, body: str, severity: str = "medium") -> str:
    """Create a GitHub issue for a security vulnerability found during scanning."""
    if not GITHUB_TOKEN:
        return "Error: GITHUB_TOKEN environment variable not set"
    try:
        repo = get_repo()
        label_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        labels = ["security"]
        severity_label = label_map.get(severity.lower())

        existing_labels = [l.name for l in repo.get_labels()]
        if severity_label and severity_label in existing_labels:
            labels.append(severity_label)

        issue = repo.create_issue(
            title=f"[SECURITY] {title}",
            body=body,
            labels=labels
        )
        return json.dumps({
            "issue_number": issue.number,
            "title": issue.title,
            "url": issue.html_url,
            "state": issue.state
        }, indent=2)
    except GithubException as e:
        return f"Failed to create issue: {e.data}"


@mcp.tool()
def get_open_issues(label: str = "security") -> str:
    """Get open GitHub issues filtered by label (default: security)."""
    if not GITHUB_TOKEN:
        return "Error: GITHUB_TOKEN environment variable not set"
    try:
        repo = get_repo()
        issues = repo.get_issues(state="open", labels=[label])
        results = []
        for issue in list(issues)[:10]:
            results.append({
                "number": issue.number,
                "title": issue.title,
                "url": issue.html_url,
                "created_at": str(issue.created_at),
                "labels": [l.name for l in issue.labels]
            })
        return json.dumps(results, indent=2) if results else f"No open issues with label: {label}"
    except GithubException as e:
        return f"Failed to fetch issues: {e.data}"


@mcp.tool()
def get_open_prs() -> str:
    """Get all open pull requests including Dependabot PRs."""
    if not GITHUB_TOKEN:
        return "Error: GITHUB_TOKEN environment variable not set"
    try:
        repo = get_repo()
        prs = repo.get_pulls(state="open")
        results = []
        for pr in list(prs)[:10]:
            results.append({
                "number": pr.number,
                "title": pr.title,
                "author": pr.user.login,
                "url": pr.html_url,
                "created_at": str(pr.created_at),
                "mergeable": pr.mergeable
            })
        return json.dumps(results, indent=2) if results else "No open PRs"
    except GithubException as e:
        return f"Failed to fetch PRs: {e.data}"


@mcp.tool()
def add_pr_comment(pr_number: int, comment: str) -> str:
    """Add a security scan result comment to a pull request."""
    if not GITHUB_TOKEN:
        return "Error: GITHUB_TOKEN environment variable not set"
    try:
        repo = get_repo()
        pr = repo.get_pull(pr_number)
        issue = repo.get_issue(pr_number)
        issue.create_comment(comment)
        return json.dumps({
            "pr_number": pr_number,
            "pr_title": pr.title,
            "comment_added": True,
            "pr_url": pr.html_url
        }, indent=2)
    except GithubException as e:
        return f"Failed to add comment: {e.data}"


@mcp.tool()
def get_recent_commits(limit: int = 5) -> str:
    """Get recent commits from the main branch."""
    if not GITHUB_TOKEN:
        return "Error: GITHUB_TOKEN environment variable not set"
    try:
        repo = get_repo()
        commits = repo.get_commits()
        results = []
        for commit in list(commits)[:limit]:
            results.append({
                "sha": commit.sha[:7],
                "message": commit.commit.message.split("\n")[0],
                "author": commit.commit.author.name,
                "date": str(commit.commit.author.date),
                "url": commit.html_url
            })
        return json.dumps(results, indent=2)
    except GithubException as e:
        return f"Failed to fetch commits: {e.data}"


@mcp.tool()
def get_workflow_runs(limit: int = 5) -> str:
    """Get recent CI/CD workflow run results — pass or fail status."""
    if not GITHUB_TOKEN:
        return "Error: GITHUB_TOKEN environment variable not set"
    try:
        repo = get_repo()
        runs = repo.get_workflow_runs()
        results = []
        for run in list(runs)[:limit]:
            results.append({
                "id": run.id,
                "name": run.name,
                "status": run.status,
                "conclusion": run.conclusion,
                "branch": run.head_branch,
                "created_at": str(run.created_at),
                "url": run.html_url
            })
        return json.dumps(results, indent=2)
    except GithubException as e:
        return f"Failed to fetch workflow runs: {e.data}"


if __name__ == "__main__":
    mcp.run()
