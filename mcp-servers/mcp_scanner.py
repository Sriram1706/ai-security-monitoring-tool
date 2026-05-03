import httpx
import json
from mcp.server.fastmcp import FastMCP

# Your live backend
API_BASE = "http://54.157.214.213"

mcp = FastMCP("AI Security Scanner")


@mcp.tool()
async def scan_content(content: str, source: str = "mcp-client") -> str:
    """Scan text content for security threats, prompt injection, and vulnerabilities."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = client.post(
            f"{API_BASE}/api/security/scan",
            json={"content": content, "source": source}
        )
        if response.status_code == 200:
            result = response.json()
            return json.dumps({
                "risk_score": result.get("risk_score"),
                "severity": result.get("severity"),
                "blocked": result.get("blocked"),
                "findings": result.get("findings", []),
                "status": result.get("status")
            }, indent=2)
        return f"Scan failed: HTTP {response.status_code} - {response.text}"


@mcp.tool()
async def scan_url(url: str) -> str:
    """Scan a URL for security vulnerabilities and threats."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = client.post(
            f"{API_BASE}/api/security/scan-url",
            json={"url": url}
        )
        if response.status_code == 200:
            result = response.json()
            return json.dumps({
                "url": url,
                "risk_score": result.get("risk_score"),
                "severity": result.get("severity"),
                "blocked": result.get("blocked"),
                "findings": result.get("findings", [])
            }, indent=2)
        return f"URL scan failed: HTTP {response.status_code} - {response.text}"


@mcp.tool()
async def process_prompt(prompt: str, provider: str = "openai") -> str:
    """Process and evaluate an AI prompt for security risks before sending to LLM."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = client.post(
            f"{API_BASE}/api/security/process-prompt",
            json={"prompt": prompt, "provider": provider}
        )
        if response.status_code == 200:
            result = response.json()
            return json.dumps({
                "allowed": result.get("allowed"),
                "risk_score": result.get("risk_score"),
                "severity": result.get("severity"),
                "findings": result.get("findings", []),
                "sanitized_prompt": result.get("sanitized_prompt")
            }, indent=2)
        return f"Prompt processing failed: HTTP {response.status_code} - {response.text}"


@mcp.tool()
async def get_security_incidents(limit: int = 10) -> str:
    """Get recent security incidents from the monitoring dashboard."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = client.get(
            f"{API_BASE}/api/incidents",
            params={"limit": limit}
        )
        if response.status_code == 200:
            incidents = response.json()
            return json.dumps(incidents, indent=2)
        return f"Failed to fetch incidents: HTTP {response.status_code}"


@mcp.tool()
async def get_threat_stats() -> str:
    """Get overall threat statistics and security metrics from the dashboard."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = client.get(f"{API_BASE}/api/stats")
        if response.status_code == 200:
            stats = response.json()
            return json.dumps(stats, indent=2)
        return f"Failed to fetch stats: HTTP {response.status_code}"


@mcp.tool()
async def health_check() -> str:
    """Check if the AI Security Monitoring Tool backend is healthy and running."""
    async with httpx.AsyncClient(timeout=10) as client:
        response = client.get(f"{API_BASE}/health")
        if response.status_code == 200:
            return f"Backend is healthy at {API_BASE}"
        return f"Backend unhealthy: HTTP {response.status_code}"


if __name__ == "__main__":
    mcp.run()
