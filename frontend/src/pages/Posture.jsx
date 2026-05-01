import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";
import SeverityBadge from "../components/SeverityBadge";

const ISSUE_MAP = {
  prompt_injection: {
    issue: "Model Injection Risk",
    recommendation: "Enforce stricter prompt validation",
  },
  jailbreak_attempt: {
    issue: "Guardrail Bypass Risk",
    recommendation: "Harden policy and jailbreak detection rules",
  },
  sensitive_data_exposure: {
    issue: "Data Exposure Risk",
    recommendation: "Mask sensitive data and tighten data access",
  },
  hallucination: {
    issue: "Model Reliability Risk",
    recommendation: "Add grounding checks and response validation",
  },
};

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export default function Posture({ globalFilters = {}, setGlobalFilters = () => {}, onOpenDrilldown = () => {} }) {
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [selectedIssue, setSelectedIssue] = useState(null);

  useEffect(() => {
    apiFetch("http://localhost:8000/logs")
      .then((res) => res.json())
      .then((data) => setLogs(Array.isArray(data) ? data : []))
      .catch(() => setLogs([]));
  }, []);

  const options = useMemo(() => {
    const providers = new Set();
    const severities = new Set();
    (logs || []).forEach((item) => {
      providers.add(item?.provider || "unknown");
      severities.add((item?.severity || "LOW").toUpperCase());
    });
    return {
      providers: Array.from(providers).sort(),
      severities: Array.from(severities).sort((a, b) => (SEVERITY_RANK[b] || 0) - (SEVERITY_RANK[a] || 0)),
    };
  }, [logs]);

  const filteredLogs = (logs || []).filter((item) => {
    const provider = item?.provider || "unknown";
    const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
    const severity = (item?.severity || "LOW").toUpperCase();
    const prompt = String(item?.prompt || "").toLowerCase();
    if (globalFilters.selectedProvider && provider !== globalFilters.selectedProvider) return false;
    if (globalFilters.selectedRiskType && riskType !== globalFilters.selectedRiskType) return false;
    if (providerFilter && provider !== providerFilter) return false;
    if (severityFilter && severity !== severityFilter) return false;
    if (search && !`${riskType} ${prompt} ${provider}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const findings = useMemo(() => {
    const counts = new Map();
    (filteredLogs || []).forEach((item) => {
      const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
      if (!ISSUE_MAP[riskType]) return;
      const severity = (item?.severity || "LOW").toUpperCase();
      if (!counts.has(riskType)) {
        counts.set(riskType, {
          risk_type: riskType,
          issue: ISSUE_MAP[riskType].issue,
          severity,
          count: 0,
          blocked: 0,
          recommendation: ISSUE_MAP[riskType].recommendation,
        });
      }
      const entry = counts.get(riskType);
      entry.count += 1;
      if ((SEVERITY_RANK[severity] || 0) > (SEVERITY_RANK[entry.severity] || 0)) entry.severity = severity;
      if (item?.blocked === true || item?.metadata?.blocked === true || item?.extra_metadata?.blocked === true) entry.blocked += 1;
    });

    return Array.from(counts.values()).sort((a, b) => b.count - a.count);
  }, [filteredLogs]);

  const severityCounts = useMemo(() => {
    const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    (filteredLogs || []).forEach((item) => {
      const sev = (item?.severity || "LOW").toUpperCase();
      if (out[sev] !== undefined) out[sev] += 1;
    });
    return out;
  }, [filteredLogs]);

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Posture</h1>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search risk/prompt/provider"
            className="xl:col-span-2 h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Severities</option>
            {options.severities.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Providers</option>
            {options.providers.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button
            type="button"
            onClick={() => {
              setSearch("");
              setSeverityFilter("");
              setProviderFilter("");
              setGlobalFilters({ selectedRiskType: "", selectedProvider: "" });
            }}
            className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-200 hover:border-cyan-500/60"
          >
            Reset Filters
          </button>
        </div>
      </section>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          ["Critical Issues", severityCounts.CRITICAL, "text-rose-300"],
          ["High Issues", severityCounts.HIGH, "text-orange-300"],
          ["Medium Issues", severityCounts.MEDIUM, "text-amber-300"],
          ["Low Issues", severityCounts.LOW, "text-emerald-300"],
          ["Tracked Risks", findings.length, "text-cyan-300"],
        ].map(([label, value, tone]) => (
          <button
            key={label}
            type="button"
            onClick={() => {
              const sev = String(label).split(" ")[0].toUpperCase();
              const rows = (filteredLogs || [])
                .filter((i) => (i?.severity || "LOW").toUpperCase() === sev)
                .map((i) => ({
                  prompt: i?.prompt || "",
                  risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
                  severity: i?.severity || "LOW",
                  timestamp: i?.created_at,
                  remediation: i?.findings?.[0]?.remediation?.join(" | "),
                }));
              onOpenDrilldown(`${sev} posture issues`, rows);
            }}
            title={`Click to inspect ${label.toLowerCase()}`}
            className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 text-left cursor-pointer hover:border-cyan-500/60 hover:shadow-[0_0_16px_rgba(56,189,248,0.16)]"
          >
            <p className="text-xs text-slate-400 uppercase">{label}</p>
            <p className={`text-2xl font-bold ${tone}`}>{value}</p>
          </button>
        ))}
      </div>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-lg font-semibold text-slate-100 mb-3">Posture Findings</h2>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="text-left py-2">Issue Type</th>
                <th className="text-left py-2">Severity</th>
                <th className="text-left py-2">Count</th>
                <th className="text-left py-2">Blocked</th>
                <th className="text-left py-2">Recommendation</th>
                <th className="text-left py-2">Action</th>
              </tr>
            </thead>
            <tbody>
              {(findings || []).map((f) => (
                <tr
                  key={`${f.risk_type}-${f.severity}`}
                  className="border-t border-slate-800/80 hover:bg-slate-800/40 transition-colors cursor-pointer interactive-row"
                  onClick={() => {
                    setGlobalFilters((p) => ({ ...p, selectedRiskType: f.risk_type }));
                    setSelectedIssue(f);
                    const rows = (filteredLogs || [])
                      .filter((i) => (i?.risk_type || i?.findings?.[0]?.risk_type || "none") === f.risk_type)
                      .map((i) => ({
                        prompt: i?.prompt || "",
                        risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
                        severity: i?.severity || "LOW",
                        timestamp: i?.created_at,
                        remediation: i?.findings?.[0]?.remediation?.join(" | "),
                      }));
                    onOpenDrilldown(f.issue, rows);
                  }}
                  title="Click to filter and open detailed posture logs"
                >
                  <td className="py-2 text-slate-100">{f.issue}</td>
                  <td className="py-2"><SeverityBadge severity={f.severity} /></td>
                  <td className="py-2 text-cyan-300 font-semibold">{f.count}</td>
                  <td className="py-2 text-rose-300 font-semibold">{f.blocked}</td>
                  <td className="py-2 text-slate-300">{f.recommendation}</td>
                  <td className="py-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedIssue(f);
                      }}
                      className="rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-xs text-cyan-200 hover:bg-cyan-500/20"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-4 text-center text-slate-400">No posture findings available</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {selectedIssue && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm p-4 flex items-center justify-center">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-slate-100">{selectedIssue.issue}</h3>
                <p className="text-xs text-slate-400 mt-1">{selectedIssue.risk_type}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedIssue(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-sm text-slate-200 hover:border-cyan-500/60"
              >
                Close
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Severity</p>
                <div className="mt-1"><SeverityBadge severity={selectedIssue.severity} /></div>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Count</p>
                <p className="text-base font-semibold text-cyan-300">{selectedIssue.count}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Blocked</p>
                <p className="text-base font-semibold text-rose-300">{selectedIssue.blocked}</p>
              </div>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3 mt-4">
              <p className="text-xs uppercase text-slate-400">Recommendation</p>
              <p className="text-sm text-slate-200 mt-1">{selectedIssue.recommendation}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
