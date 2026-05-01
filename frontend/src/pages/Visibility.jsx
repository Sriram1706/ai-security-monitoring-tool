import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";

export default function Visibility({ globalFilters = {}, setGlobalFilters = () => {}, onOpenDrilldown = () => {} }) {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    apiFetch("/api/logs")
      .then((res) => res.json())
      .then((data) => setLogs(Array.isArray(data) ? data : []))
      .catch(() => setLogs([]));
  }, []);

  const summary = useMemo(() => {
    const providers = new Set();
    const riskTypes = new Set();
    const table = new Map();

    (logs || []).forEach((item) => {
      const provider = item?.provider || "unknown";
      if (globalFilters.selectedProvider && provider !== globalFilters.selectedProvider) return;
      providers.add(provider);

      const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
      if (globalFilters.selectedRiskType && riskType !== globalFilters.selectedRiskType) return;
      riskTypes.add(riskType);
      const key = `${provider}::${riskType}`;
      table.set(key, (table.get(key) || 0) + 1);
    });

    const rows = Array.from(table.entries())
      .map(([key, count]) => {
        const [provider, risk_type] = key.split("::");
        return { provider, risk_type, count };
      })
      .sort((a, b) => b.count - a.count);

    return {
      totalRequests: (logs || []).length,
      uniqueProviders: providers.size,
      uniqueRiskTypes: riskTypes.size,
      rows,
    };
  }, [logs, globalFilters.selectedProvider, globalFilters.selectedRiskType]);

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Visibility</h1>
      <div className="flex flex-wrap gap-2">
        {globalFilters.selectedProvider && (
          <button type="button" onClick={() => setGlobalFilters((p) => ({ ...p, selectedProvider: "" }))} title="Clear provider filter" className="text-xs rounded-full border border-slate-700 px-3 py-1 cursor-pointer hover:border-cyan-500/60">
            Provider: {globalFilters.selectedProvider} x
          </button>
        )}
        {globalFilters.selectedRiskType && (
          <button type="button" onClick={() => setGlobalFilters((p) => ({ ...p, selectedRiskType: "" }))} title="Clear risk filter" className="text-xs rounded-full border border-slate-700 px-3 py-1 cursor-pointer hover:border-cyan-500/60">
            Risk: {globalFilters.selectedRiskType} x
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <button
          type="button"
          onClick={() => {
            const rows = (logs || []).map((i) => ({
              prompt: i?.prompt || "",
              risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
              severity: i?.severity || "LOW",
              timestamp: i?.created_at,
              remediation: i?.findings?.[0]?.remediation?.join(" | "),
            }));
            onOpenDrilldown("Visibility: All Requests", rows);
          }}
          title="Click to inspect all visibility logs"
          className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 text-left interactive-card"
        >
          <p className="text-xs text-slate-400 uppercase">Total Requests</p>
          <p className="text-2xl font-bold text-slate-100">{summary.totalRequests}</p>
        </button>
        <button
          type="button"
          onClick={() => {
            const rows = (summary.rows || []).map((r) => ({
              prompt: `Provider ${r.provider}: ${r.count} request(s)`,
              risk_type: r.risk_type,
              severity: "LOW",
              timestamp: new Date().toISOString(),
              remediation: "Filter by provider for detailed inspection.",
            }));
            onOpenDrilldown("Visibility: Providers", rows);
          }}
          title="Click to inspect provider breakdown"
          className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 text-left interactive-card"
        >
          <p className="text-xs text-slate-400 uppercase">Unique Providers</p>
          <p className="text-2xl font-bold text-slate-100">{summary.uniqueProviders}</p>
        </button>
        <button
          type="button"
          onClick={() => {
            const rows = (summary.rows || []).map((r) => ({
              prompt: `Risk ${r.risk_type}: ${r.count} request(s)`,
              risk_type: r.risk_type,
              severity: "LOW",
              timestamp: new Date().toISOString(),
              remediation: "Filter by risk type for full context.",
            }));
            onOpenDrilldown("Visibility: Risk Types", rows);
          }}
          title="Click to inspect risk-type breakdown"
          className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 text-left interactive-card"
        >
          <p className="text-xs text-slate-400 uppercase">Unique Risk Types</p>
          <p className="text-2xl font-bold text-slate-100">{summary.uniqueRiskTypes}</p>
        </button>
      </div>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-lg font-semibold text-slate-100 mb-3">Usage by Provider and Risk Type</h2>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="text-left py-2">Provider</th>
                <th className="text-left py-2">Risk Type</th>
                <th className="text-left py-2">Count</th>
              </tr>
            </thead>
            <tbody>
              {(summary.rows || []).map((row, idx) => (
                <tr
                  key={`${row.provider}-${row.risk_type}-${idx}`}
                  className="border-t border-slate-800/80 hover:bg-slate-800/40 transition-colors interactive-row"
                >
                  <td
                    className="py-2 text-slate-200 cursor-pointer hover:text-cyan-300"
                    onClick={() => {
                      setGlobalFilters((p) => ({ ...p, selectedProvider: row.provider }));
                      const rows = (logs || [])
                        .filter((i) => (i?.provider || "unknown") === row.provider)
                        .map((i) => ({
                          prompt: i?.prompt || "",
                          risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
                          severity: i?.severity || "LOW",
                          timestamp: i?.created_at,
                          remediation: i?.findings?.[0]?.remediation?.join(" | "),
                        }));
                      onOpenDrilldown(`Provider: ${row.provider}`, rows);
                    }}
                    title="Click to filter and inspect this provider"
                  >
                    {row.provider}
                  </td>
                  <td
                    className="py-2 text-cyan-300 cursor-pointer hover:text-cyan-200"
                    onClick={() => {
                      setGlobalFilters((p) => ({ ...p, selectedRiskType: row.risk_type }));
                      const rows = (logs || [])
                        .filter((i) => (i?.risk_type || i?.findings?.[0]?.risk_type || "none") === row.risk_type)
                        .map((i) => ({
                          prompt: i?.prompt || "",
                          risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
                          severity: i?.severity || "LOW",
                          timestamp: i?.created_at,
                          remediation: i?.findings?.[0]?.remediation?.join(" | "),
                        }));
                      onOpenDrilldown(`Risk Type: ${row.risk_type}`, rows);
                    }}
                    title="Click to filter and inspect this risk type"
                  >
                    {row.risk_type}
                  </td>
                  <td className="py-2 text-slate-200 font-semibold">{row.count}</td>
                </tr>
              ))}
              {summary.rows.length === 0 && (
                <tr>
                  <td colSpan={3} className="py-4 text-center text-slate-400">No data available</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
