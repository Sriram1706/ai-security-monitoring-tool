import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";
import SeverityBadge from "../components/SeverityBadge";

const DATA_RISK_TYPES = new Set([
  "sensitive_data_exposure",
  "data_exfiltration",
  "hardcoded_secret",
  "secret_leak",
  "pii_exposure",
]);

const PII_PHI_PCI_RULES = [
  { id: "email", label: "Email", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { id: "phone", label: "Phone", regex: /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/ },
  { id: "ssn", label: "SSN", regex: /\b\d{3}-\d{2}-\d{4}\b/ },
  { id: "credit_card", label: "Credit Card", regex: /\b(?:\d[ -]*?){13,19}\b/ },
  { id: "cvv", label: "CVV", regex: /\b(?:cvv|cvc)\s*[:=]?\s*\d{3,4}\b/i },
  { id: "phi_keywords", label: "PHI Keyword", regex: /\b(patient|diagnosis|medical record|mrn|prescription|lab result|dob)\b/i },
];

const SECRET_RULES = [
  { id: "openai_key", label: "OpenAI Key", regex: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { id: "aws_access_key", label: "AWS Access Key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "github_token", label: "GitHub Token", regex: /\bghp_[A-Za-z0-9]{30,}\b/ },
  { id: "jwt_token", label: "JWT Token", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b/ },
  { id: "private_key", label: "Private Key Block", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i },
  { id: "generic_api_key", label: "Generic API Key", regex: /\b(?:api[_-]?key|token|secret)\s*[:=]\s*['"]?[A-Za-z0-9._\-]{12,}['"]?\b/i },
  { id: "bearer", label: "Bearer Token", regex: /\bBearer\s+[A-Za-z0-9._\-]{16,}\b/i },
];

function tsLabel(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(dt);
}

export default function DataSecurity() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [detectorFilter, setDetectorFilter] = useState("");

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const res = await apiFetch("/api/logs?limit=1000&sort_by=timestamp&sort_dir=desc");
        if (!res.ok) {
          throw new Error(`Failed to load data security logs (${res.status})`);
        }
        const json = await res.json();
        setLogs(Array.isArray(json) ? json : []);
      } catch (e) {
        setLogs([]);
        setError(e?.message || "Unable to load data security telemetry.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const dsRows = useMemo(() => {
    return (logs || []).filter((row) => {
      const rt = String(row?.risk_type || row?.findings?.[0]?.risk_type || "none").toLowerCase();
      return DATA_RISK_TYPES.has(rt);
    });
  }, [logs]);

  const filtered = useMemo(() => {
    return dsRows.filter((row) => {
      const sev = String(row?.severity || "LOW").toUpperCase();
      const text = `${row?.prompt || ""} ${row?.provider || ""} ${row?.source || ""} ${row?.risk_type || ""}`.toLowerCase();
      if (severity && sev !== severity) return false;
      if (search && !text.includes(search.toLowerCase())) return false;
      return true;
    });
  }, [dsRows, severity, search]);

  const enriched = useMemo(() => {
    return filtered.map((row) => {
      const prompt = String(row?.prompt || "");
      const piiMatches = PII_PHI_PCI_RULES.filter((r) => r.regex.test(prompt)).map((r) => r.label);
      const secretMatches = SECRET_RULES.filter((r) => r.regex.test(prompt)).map((r) => r.label);
      const rt = String(row?.risk_type || row?.findings?.[0]?.risk_type || "unknown").toLowerCase();
      let dataClass = "Internal";
      if (secretMatches.length > 0 || piiMatches.length > 0) dataClass = "Restricted";
      else if (rt === "sensitive_data_exposure" || rt === "data_exfiltration") dataClass = "Confidential";
      return {
        ...row,
        piiMatches,
        secretMatches,
        dataClass,
      };
    });
  }, [filtered]);

  const detectorFiltered = useMemo(() => {
    if (!detectorFilter) return enriched;
    if (detectorFilter === "pii_phi_pci") return enriched.filter((r) => r.piiMatches.length > 0);
    if (detectorFilter === "secrets") return enriched.filter((r) => r.secretMatches.length > 0);
    if (detectorFilter === "restricted") return enriched.filter((r) => r.dataClass === "Restricted");
    return enriched;
  }, [enriched, detectorFilter]);

  const summary = useMemo(() => {
    const out = { total: 0, blocked: 0, critical: 0, high: 0 };
    for (const row of dsRows) {
      out.total += 1;
      const sev = String(row?.severity || "LOW").toUpperCase();
      const blocked = row?.metadata?.blocked === true || row?.extra_metadata?.blocked === true;
      if (blocked) out.blocked += 1;
      if (sev === "CRITICAL") out.critical += 1;
      if (sev === "HIGH") out.high += 1;
    }
    return out;
  }, [dsRows]);

  const engineStats = useMemo(() => {
    const out = {
      publicCount: 0,
      internalCount: 0,
      confidentialCount: 0,
      restrictedCount: 0,
      piiHits: 0,
      secretHits: 0,
      piiRules: {},
      secretRules: {},
    };
    for (const row of enriched) {
      const cls = row.dataClass;
      if (cls === "Restricted") out.restrictedCount += 1;
      else if (cls === "Confidential") out.confidentialCount += 1;
      else if (cls === "Internal") out.internalCount += 1;
      else out.publicCount += 1;

      if (row.piiMatches.length > 0) {
        out.piiHits += 1;
        for (const m of row.piiMatches) out.piiRules[m] = (out.piiRules[m] || 0) + 1;
      }
      if (row.secretMatches.length > 0) {
        out.secretHits += 1;
        for (const m of row.secretMatches) out.secretRules[m] = (out.secretRules[m] || 0) + 1;
      }
    }
    return out;
  }, [enriched]);

  const topPiiRules = useMemo(
    () =>
      Object.entries(engineStats.piiRules)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
    [engineStats],
  );

  const topSecretRules = useMemo(
    () =>
      Object.entries(engineStats.secretRules)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
    [engineStats],
  );

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Data Security</h1>

      {loading && <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-slate-300">Loading data-security telemetry...</div>}
      {error && <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-rose-300">{error}</div>}

      {!loading && !error && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Total Data Risks</p>
              <p className="text-2xl font-bold text-slate-100">{summary.total}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Blocked</p>
              <p className="text-2xl font-bold text-rose-300">{summary.blocked}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Critical</p>
              <p className="text-2xl font-bold text-red-400">{summary.critical}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">High</p>
              <p className="text-2xl font-bold text-orange-300">{summary.high}</p>
            </div>
          </div>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Data Classification Engine</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
                <p className="text-xs uppercase text-slate-400">Restricted</p>
                <p className="text-2xl font-bold text-rose-300">{engineStats.restrictedCount}</p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
                <p className="text-xs uppercase text-slate-400">Confidential</p>
                <p className="text-2xl font-bold text-orange-300">{engineStats.confidentialCount}</p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
                <p className="text-xs uppercase text-slate-400">Internal</p>
                <p className="text-2xl font-bold text-cyan-300">{engineStats.internalCount}</p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
                <p className="text-xs uppercase text-slate-400">Public</p>
                <p className="text-2xl font-bold text-emerald-300">{engineStats.publicCount}</p>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
              <h2 className="text-lg font-semibold text-slate-100">PII/PHI/PCI Detection</h2>
              <p className="text-sm text-slate-400 mt-1">Rows with PII/PHI/PCI signals: <span className="text-cyan-300 font-semibold">{engineStats.piiHits}</span></p>
              <div className="mt-3 space-y-2 text-sm">
                {topPiiRules.length === 0 ? (
                  <p className="text-slate-500">No pattern matches found.</p>
                ) : (
                  topPiiRules.map((item) => (
                    <div key={item.name} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
                      <span className="text-slate-200">{item.name}</span>
                      <span className="text-cyan-300 font-semibold">{item.count}</span>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
              <h2 className="text-lg font-semibold text-slate-100">Secrets Detection</h2>
              <p className="text-sm text-slate-400 mt-1">Rows with secret leakage signals: <span className="text-cyan-300 font-semibold">{engineStats.secretHits}</span></p>
              <div className="mt-3 space-y-2 text-sm">
                {topSecretRules.length === 0 ? (
                  <p className="text-slate-500">No pattern matches found.</p>
                ) : (
                  topSecretRules.map((item) => (
                    <div key={item.name} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
                      <span className="text-slate-200">{item.name}</span>
                      <span className="text-cyan-300 font-semibold">{item.count}</span>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-2 mb-3">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search prompt/provider/source"
                className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              />
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <select
                value={detectorFilter}
                onChange={(e) => setDetectorFilter(e.target.value)}
                className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              >
                <option value="">All Detection Types</option>
                <option value="pii_phi_pci">PII / PHI / PCI</option>
                <option value="secrets">Secrets</option>
                <option value="restricted">Restricted Data</option>
              </select>
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSeverity("");
                  setDetectorFilter("");
                }}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-200 hover:border-cyan-500/50"
              >
                Reset Filters
              </button>
            </div>

            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead className="text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="text-left py-2 pr-3">Risk Type</th>
                    <th className="text-left py-2 pr-3">Severity</th>
                    <th className="text-left py-2 pr-3">Provider</th>
                    <th className="text-left py-2 pr-3">Source</th>
                    <th className="text-left py-2 pr-3">Class</th>
                    <th className="text-left py-2 pr-3">PII/PHI/PCI</th>
                    <th className="text-left py-2 pr-3">Secrets</th>
                    <th className="text-left py-2 pr-3">Risk Score</th>
                    <th className="text-left py-2 pr-3">Blocked</th>
                    <th className="text-left py-2">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {detectorFiltered.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="py-5 text-slate-400">
                        No data-security findings for selected filters.
                      </td>
                    </tr>
                  ) : (
                    detectorFiltered.slice(0, 300).map((row) => {
                      const rt = String(row?.risk_type || row?.findings?.[0]?.risk_type || "unknown");
                      const blocked = row?.metadata?.blocked === true || row?.extra_metadata?.blocked === true;
                      return (
                        <tr key={`${row?.id}-${row?.created_at}`} className="border-b border-slate-800/50 hover:bg-slate-900/40">
                          <td className="py-2 pr-3 text-cyan-300">{rt}</td>
                          <td className="py-2 pr-3">
                            <SeverityBadge severity={String(row?.severity || "LOW").toUpperCase()} />
                          </td>
                          <td className="py-2 pr-3 text-slate-200">{row?.provider || "unknown"}</td>
                          <td className="py-2 pr-3 text-slate-200">{row?.source || "unknown"}</td>
                          <td className="py-2 pr-3">
                            <span className={`text-xs px-2 py-1 rounded border ${
                              row.dataClass === "Restricted"
                                ? "text-rose-300 border-rose-500/40 bg-rose-500/10"
                                : row.dataClass === "Confidential"
                                  ? "text-orange-300 border-orange-500/40 bg-orange-500/10"
                                  : "text-cyan-300 border-cyan-500/40 bg-cyan-500/10"
                            }`}>
                              {row.dataClass}
                            </span>
                          </td>
                          <td className="py-2 pr-3 text-slate-300">{row.piiMatches.length > 0 ? row.piiMatches.join(", ") : "-"}</td>
                          <td className="py-2 pr-3 text-slate-300">{row.secretMatches.length > 0 ? row.secretMatches.join(", ") : "-"}</td>
                          <td className="py-2 pr-3 text-cyan-300 font-semibold">{Number(row?.risk_score || 0)}</td>
                          <td className="py-2 pr-3">{blocked ? <span className="text-rose-300">YES</span> : <span className="text-emerald-300">NO</span>}</td>
                          <td className="py-2 text-slate-400">{tsLabel(row?.created_at)}</td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
