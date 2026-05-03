import httpx
import json
from mcp.server.fastmcp import FastMCP

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1"

mcp = FastMCP("CVE Lookup")


@mcp.tool()
async def lookup_cve(cve_id: str) -> str:
    """Look up details for a specific CVE ID (e.g. CVE-2024-1234)."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(NVD_API, params={"cveId": cve_id})
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return f"No data found for {cve_id}"
            cve = vulns[0]["cve"]
            metrics = cve.get("metrics", {})
            cvss = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            )
            description = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available"
            )
            return json.dumps({
                "cve_id": cve_id,
                "description": description,
                "severity": cvss.get("baseSeverity", "UNKNOWN"),
                "score": cvss.get("baseScore", "N/A"),
                "published": cve.get("published", "N/A"),
                "last_modified": cve.get("lastModified", "N/A"),
                "references": [r["url"] for r in cve.get("references", [])[:3]]
            }, indent=2)
        return f"CVE lookup failed: HTTP {response.status_code}"


@mcp.tool()
async def search_cves_by_keyword(keyword: str, limit: int = 5) -> str:
    """Search for CVEs by keyword (e.g. 'fastapi', 'sqlalchemy', 'lodash')."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": limit}
        )
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return f"No CVEs found for keyword: {keyword}"
            results = []
            for v in vulns:
                cve = v["cve"]
                metrics = cve.get("metrics", {})
                cvss = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                    or {}
                )
                description = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description"
                )
                results.append({
                    "cve_id": cve["id"],
                    "severity": cvss.get("baseSeverity", "UNKNOWN"),
                    "score": cvss.get("baseScore", "N/A"),
                    "description": description[:200] + "..." if len(description) > 200 else description
                })
            return json.dumps(results, indent=2)
        return f"CVE search failed: HTTP {response.status_code}"


@mcp.tool()
async def check_package_vulnerabilities(package: str, ecosystem: str = "PyPI") -> str:
    """Check if a package has known vulnerabilities. Ecosystem: PyPI, npm, Go, Maven, etc."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{OSV_API}/query",
            json={"package": {"name": package, "ecosystem": ecosystem}}
        )
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            if not vulns:
                return f"No known vulnerabilities found for {package} ({ecosystem})"
            results = []
            for v in vulns[:5]:
                results.append({
                    "id": v.get("id"),
                    "summary": v.get("summary", "No summary"),
                    "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                    "affected_versions": [
                        r.get("ranges", [{}])[0].get("events", [])
                        for r in v.get("affected", [])[:1]
                    ],
                    "fixed_in": next(
                        (
                            e.get("fixed") for r in v.get("affected", [])
                            for rng in r.get("ranges", [])
                            for e in rng.get("events", [])
                            if e.get("fixed")
                        ),
                        "No fix available"
                    )
                })
            return json.dumps({
                "package": package,
                "ecosystem": ecosystem,
                "total_vulnerabilities": len(vulns),
                "top_5": results
            }, indent=2)
        return f"Package check failed: HTTP {response.status_code}"


@mcp.tool()
async def get_severity_summary(cve_id: str) -> str:
    """Get a plain-English severity summary for a CVE — great for reports and GitHub issues."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(NVD_API, params={"cveId": cve_id})
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return f"No data found for {cve_id}"
            cve = vulns[0]["cve"]
            metrics = cve.get("metrics", {})
            cvss = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                or {}
            )
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            description = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available"
            )
            if score >= 9.0:
                risk = "CRITICAL — immediate action required"
            elif score >= 7.0:
                risk = "HIGH — fix within 7 days"
            elif score >= 4.0:
                risk = "MEDIUM — fix within 30 days"
            else:
                risk = "LOW — fix in next release cycle"

            return (
                f"{cve_id} | Score: {score} | Severity: {severity}\n"
                f"Risk: {risk}\n"
                f"Summary: {description[:300]}"
            )
        return f"Severity lookup failed: HTTP {response.status_code}"


if __name__ == "__main__":
    mcp.run()
