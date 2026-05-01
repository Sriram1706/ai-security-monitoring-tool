import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";

const severityRank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const csvEscape = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;

const toCsv = (rows) => {
  const header = ["id", "prompt", "risk_type", "severity", "provider", "status", "blocked", "risk_score", "timestamp"];
  const data = (rows || []).map((r) => [
    r?.id || "",
    r?.prompt || "",
    r?.risk_type || r?.findings?.[0]?.risk_type || "none",
    (r?.severity || "LOW").toUpperCase(),
    r?.provider || "unknown",
    r?.extra_metadata?.status || "SAFE",
    r?.extra_metadata?.blocked ? "true" : "false",
    Number(r?.risk_score || 0),
    r?.created_at || "",
  ]);
  return [header, ...data].map((line) => line.map(csvEscape).join(",")).join("\n");
};

const downloadBlob = (content, fileName, type) => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
};

export default function Reports({ globalFilters = {}, onOpenDrilldown = () => {} }) {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [analytics, setAnalytics] = useState({});
  const [threatSummary, setThreatSummary] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      apiFetch("http://localhost:8000/logs?limit=1000").then((res) => (res.ok ? res.json() : [])),
      apiFetch("http://localhost:8000/alerts").then((res) => (res.ok ? res.json() : [])),
      apiFetch("http://localhost:8000/analytics").then((res) => (res.ok ? res.json() : {})),
      apiFetch("http://localhost:8000/threat-summary").then((res) => (res.ok ? res.json() : {})),
    ])
      .then(([logsData, alertsData, analyticsData, summaryData]) => {
        setLogs(Array.isArray(logsData) ? logsData : []);
        setAlerts(Array.isArray(alertsData) ? alertsData : []);
        setAnalytics(analyticsData || {});
        setThreatSummary(summaryData || {});
      })
      .catch(() => {
        setLogs([]);
        setAlerts([]);
        setAnalytics({});
        setThreatSummary({});
      })
      .finally(() => setLoading(false));
  }, []);

  const filteredLogs = (logs || []).filter((item) => {
    const provider = item?.provider || "unknown";
    const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
    if (globalFilters.selectedProvider && provider !== globalFilters.selectedProvider) return false;
    if (globalFilters.selectedRiskType && riskType !== globalFilters.selectedRiskType) return false;
    return true;
  });

  const summary = useMemo(() => {
    const riskCounts = new Map();
    const providerCounts = new Map();
    let highestSeverity = "LOW";

    (filteredLogs || []).forEach((item) => {
      const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
      if (riskType !== "none") riskCounts.set(riskType, (riskCounts.get(riskType) || 0) + 1);
      const provider = item?.provider || "unknown";
      providerCounts.set(provider, (providerCounts.get(provider) || 0) + 1);
      const sev = (item?.severity || "LOW").toUpperCase();
      if ((severityRank[sev] || 1) > (severityRank[highestSeverity] || 1)) highestSeverity = sev;
    });

    const mostFrequentThreat = Array.from(riskCounts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || "none";
    const topProvider = Array.from(providerCounts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown";
    const blocked = (filteredLogs || []).filter((i) => Boolean(i?.extra_metadata?.blocked)).length;
    const blockedRate = filteredLogs.length > 0 ? Math.round((blocked / filteredLogs.length) * 100) : 0;
    return {
      totalAttacks: filteredLogs.length,
      mostFrequentThreat,
      highestSeverity,
      topProvider,
      blocked,
      blockedRate,
    };
  }, [filteredLogs]);

  const reportPackage = useMemo(() => {
    return {
      generated_at: new Date().toISOString(),
      filters: globalFilters,
      summary: {
        ...summary,
        active_alerts: (alerts || []).length,
        total_scans: analytics?.total_scans || 0,
        avg_risk_score: analytics?.avg_risk_score || 0,
        threat_summary: threatSummary || {},
      },
      logs: filteredLogs,
      alerts,
      analytics,
      threat_summary: threatSummary,
    };
  }, [globalFilters, summary, filteredLogs, alerts, analytics, threatSummary]);

  const downloadDetailedCsv = () => {
    downloadBlob(toCsv(filteredLogs), `ai-security-detailed-${Date.now()}.csv`, "text/csv;charset=utf-8;");
  };

  const downloadExecutiveCsv = () => {
    const rows = [
      ["metric", "value"],
      ["total_attacks", summary.totalAttacks],
      ["blocked_requests", summary.blocked],
      ["blocked_rate_percent", `${summary.blockedRate}%`],
      ["most_frequent_threat", summary.mostFrequentThreat],
      ["highest_severity", summary.highestSeverity],
      ["top_provider", summary.topProvider],
      ["active_alerts", (alerts || []).length],
      ["avg_risk_score", Number(analytics?.avg_risk_score || 0).toFixed(2)],
    ];
    const csv = rows.map((line) => line.map(csvEscape).join(",")).join("\n");
    downloadBlob(csv, `ai-security-executive-${Date.now()}.csv`, "text/csv;charset=utf-8;");
  };

  const downloadJson = () => {
    downloadBlob(JSON.stringify(reportPackage, null, 2), `ai-security-report-${Date.now()}.json`, "application/json;charset=utf-8;");
  };

  const downloadMarkdown = () => {
    const md = [
      "# AI Security Report",
      "",
      `Generated: ${new Date().toLocaleString()}`,
      `Total Attacks: ${summary.totalAttacks}`,
      `Blocked Requests: ${summary.blocked} (${summary.blockedRate}%)`,
      `Most Frequent Threat: ${summary.mostFrequentThreat}`,
      `Highest Severity: ${summary.highestSeverity}`,
      `Top Provider: ${summary.topProvider}`,
      "",
      "## Top Findings",
      "",
      ...(filteredLogs || []).slice(0, 20).map((item, idx) => {
        const rt = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
        return `${idx + 1}. [${(item?.severity || "LOW").toUpperCase()}] ${rt} | ${(item?.provider || "unknown")} | ${(item?.created_at || "").toString()}`;
      }),
      "",
    ].join("\n");
    downloadBlob(md, `ai-security-report-${Date.now()}.md`, "text/markdown;charset=utf-8;");
  };

  const exportPdfViaPrint = () => {
    const html = `
      <html>
        <head><title>AI Security Report</title></head>
        <body style="font-family: Arial, sans-serif; padding: 24px;">
          <h1>AI Security Report</h1>
          <p>Generated: ${new Date().toLocaleString()}</p>
          <p>Total Attacks: ${summary.totalAttacks}</p>
          <p>Blocked Requests: ${summary.blocked} (${summary.blockedRate}%)</p>
          <p>Most Frequent Threat: ${summary.mostFrequentThreat}</p>
          <p>Highest Severity: ${summary.highestSeverity}</p>
          <p>Top Provider: ${summary.topProvider}</p>
          <h2>Top 25 Events</h2>
          <table border="1" cellspacing="0" cellpadding="6" style="border-collapse: collapse; width: 100%;">
            <thead><tr><th>ID</th><th>Risk</th><th>Severity</th><th>Provider</th><th>Score</th><th>Timestamp</th></tr></thead>
            <tbody>
              ${(filteredLogs || []).slice(0, 25).map((item) => `
                <tr>
                  <td>${item?.id || ""}</td>
                  <td>${item?.risk_type || item?.findings?.[0]?.risk_type || "none"}</td>
                  <td>${(item?.severity || "LOW").toUpperCase()}</td>
                  <td>${item?.provider || "unknown"}</td>
                  <td>${Number(item?.risk_score || 0)}</td>
                  <td>${item?.created_at || ""}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </body>
      </html>`;
    const win = window.open("", "_blank", "width=1100,height=800");
    if (!win) return;
    win.document.write(html);
    win.document.close();
    win.focus();
    setTimeout(() => win.print(), 500);
  };

  if (loading) {
    return <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 text-slate-300">Loading reports...</div>;
  }

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Reports</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-6 gap-3">
        {[
          ["Total Attacks", summary.totalAttacks, "text-slate-100"],
          ["Blocked", summary.blocked, "text-rose-300"],
          ["Blocked Rate", `${summary.blockedRate}%`, "text-orange-300"],
          ["Most Frequent Threat", summary.mostFrequentThreat, "text-cyan-300"],
          ["Top Provider", summary.topProvider, "text-emerald-300"],
          ["Highest Severity", summary.highestSeverity, "text-rose-300"],
        ].map(([label, value, tone]) => (
          <button
            key={label}
            type="button"
            onClick={() =>
              onOpenDrilldown(
                `Report: ${label}`,
                (filteredLogs || []).map((i) => ({
                  prompt: i?.prompt || "",
                  risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
                  severity: i?.severity || "LOW",
                  timestamp: i?.created_at,
                  remediation: i?.findings?.[0]?.remediation?.join(" | "),
                })),
              )
            }
            title={`Click to inspect ${label.toLowerCase()}`}
            className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 text-left interactive-card"
          >
            <p className="text-xs text-slate-400 uppercase">{label}</p>
            <p className={`text-2xl font-bold ${tone}`}>{value}</p>
          </button>
        ))}
      </div>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-lg font-semibold text-slate-100">Export Security Reports</h2>
        <p className="text-sm text-slate-300 mt-1">Choose your format based on SOC workflow: detailed, executive, machine-readable, or presentation-ready.</p>
        <div className="flex flex-wrap gap-3 mt-4">
          <button title="Download all filtered events as detailed CSV" onClick={downloadDetailedCsv} className="rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2 font-semibold cursor-pointer">Download Detailed CSV</button>
          <button title="Download executive KPI summary as CSV" onClick={downloadExecutiveCsv} className="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2 font-semibold cursor-pointer">Download Executive CSV</button>
          <button title="Download full report package as JSON" onClick={downloadJson} className="rounded-xl bg-emerald-600 hover:bg-emerald-500 px-4 py-2 font-semibold cursor-pointer">Download JSON</button>
          <button title="Download report brief as Markdown" onClick={downloadMarkdown} className="rounded-xl bg-violet-600 hover:bg-violet-500 px-4 py-2 font-semibold cursor-pointer">Download Markdown</button>
          <button title="Open printable report (Save as PDF)" onClick={exportPdfViaPrint} className="rounded-xl bg-amber-600 hover:bg-amber-500 px-4 py-2 font-semibold cursor-pointer">Export PDF (Print)</button>
        </div>
      </section>
    </div>
  );
}
