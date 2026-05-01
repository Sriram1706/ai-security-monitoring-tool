import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiFetch } from "../lib/apiFetch";
import SeverityBadge from "../components/SeverityBadge";

const severityRank = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function getStatus(item) {
  const metadataStatus = item?.metadata?.status || item?.extra_metadata?.status;
  if (metadataStatus) {
    const normalized = String(metadataStatus).toUpperCase();
    if (normalized === "BLOCKED") return "BLOCKED";
    if (normalized === "WARNING") return "FLAGGED";
    if (normalized === "SAFE") return "SAFE";
  }

  if (item?.blocked === true || item?.metadata?.blocked === true || item?.extra_metadata?.blocked === true) {
    return "BLOCKED";
  }

  const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
  return riskType === "none" ? "SAFE" : "DETECTED";
}

function badgeClass(status) {
  if (status === "SAFE") return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
  if (status === "FLAGGED") return "bg-amber-500/15 text-amber-300 border-amber-500/40";
  return "bg-rose-500/15 text-rose-300 border-rose-500/40";
}

function owaspFromRisk(riskType) {
  const map = {
    prompt_injection: "LLM01: Prompt Injection",
    jailbreak_attempt: "LLM01: Prompt Injection",
    indirect_prompt_injection: "LLM01: Prompt Injection",
    policy_violation: "LLM02: Insecure Output Handling",
    toxicity_or_harm: "LLM02: Insecure Output Handling",
    adversarial_input: "LLM04: Model Denial of Service",
    sensitive_data_exposure: "LLM06: Sensitive Information Disclosure",
    data_exfiltration: "LLM06: Sensitive Information Disclosure",
    model_misuse: "LLM08: Excessive Agency",
    illegal_activity: "LLM08: Excessive Agency",
    hallucination: "LLM09: Overreliance",
  };
  if (riskType === "none") return "N/A (No threat)";
  return map[riskType] || "LLM10: Model Theft";
}

function frameworkLabel(value) {
  if (value === "OWASP_AGENTIC") return "Agentic";
  if (value === "OWASP_LLM_TOP10") return "LLM Top10";
  return value;
}

function complianceKey(mapping) {
  const fw = String(mapping?.framework || "").trim();
  const id = String(mapping?.control_id || "").trim();
  if (!fw || !id) return "";
  return `${fw}:${id}`;
}

function complianceLabel(key) {
  if (!key) return "";
  const [fw, id] = String(key).split(":");
  const fwLabel = fw === "NIST_AI_RMF" ? "NIST AI RMF" : fw === "ISO_IEC_42001" ? "ISO/IEC 42001" : fw === "OWASP_LLM_TOP10" ? "OWASP LLM Top10" : fw;
  return `${fwLabel} ${id || ""}`.trim();
}

function parseBackendTimestamp(value) {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "number") {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  let raw = String(value).trim();
  if (!raw) return null;

  // Normalize common backend formats: "YYYY-MM-DD HH:mm:ss(.ffffff)" -> ISO
  raw = raw.replace(" ", "T");
  // JS Date supports milliseconds; backend may emit microseconds.
  raw = raw.replace(/\.(\d{3})\d+/, ".$1");

  const hasTimezone = /[zZ]|[+-]\d{2}:\d{2}$/.test(raw);
  const normalized = hasTimezone ? raw : `${raw}Z`; // treat naive timestamps as UTC
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? null : d;
}

function formatISTTimestamp(value) {
  const dt = parseBackendTimestamp(value);
  if (!dt) return "-";
  const formatted = new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(dt);
  return `${formatted} IST`;
}

export default function Requests() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState([]);
  const [codeSummary, setCodeSummary] = useState({
    total_findings: 0,
    findings_last_24h: 0,
    severity_distribution: {},
    top_finding_types: [],
  });
  const [riskType, setRiskType] = useState("");
  const [severity, setSeverity] = useState("");
  const [provider, setProvider] = useState("");
  const [source, setSource] = useState("");
  const [framework, setFramework] = useState("");
  const [atlasTechnique, setAtlasTechnique] = useState("");
  const [compliance, setCompliance] = useState("");
  const [minRiskScore, setMinRiskScore] = useState("");
  const [maxRiskScore, setMaxRiskScore] = useState("");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("timestamp");
  const [sortDir, setSortDir] = useState("desc");

  useEffect(() => {
    const parsedMin = minRiskScore === "" ? null : Number(minRiskScore);
    const parsedMax = maxRiskScore === "" ? null : Number(maxRiskScore);
    const hasValidMin = Number.isFinite(parsedMin) && parsedMin >= 0;
    const hasValidMax = Number.isFinite(parsedMax) && parsedMax >= 0;

    const params = new URLSearchParams();
    if (riskType) params.set("risk_type", riskType);
    if (severity) params.set("severity", severity);
    if (provider) params.set("provider", provider);
    if (hasValidMin) params.set("min_risk_score", String(parsedMin));
    if (hasValidMax) params.set("max_risk_score", String(parsedMax));
    if (hasValidMin && hasValidMax && parsedMin > parsedMax) {
      params.delete("max_risk_score");
    }
    if (sortBy) params.set("sort_by", sortBy);
    if (sortDir) params.set("sort_dir", sortDir);
    params.set("limit", "1000");
    const logsUrl = `/api/logs?${params.toString()}`;

    apiFetch(logsUrl)
      .then((res) => res.json())
      .then((data) => setLogs(Array.isArray(data) ? data : []))
      .catch(() => setLogs([]));
  }, [riskType, severity, provider, minRiskScore, maxRiskScore, sortBy, sortDir]);

  useEffect(() => {
    apiFetch("/api/code-findings/summary")
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("summary failed"))))
      .then((data) =>
        setCodeSummary({
          total_findings: Number(data?.total_findings || 0),
          findings_last_24h: Number(data?.findings_last_24h || 0),
          severity_distribution: data?.severity_distribution || {},
          top_finding_types: Array.isArray(data?.top_finding_types) ? data.top_finding_types : [],
        })
      )
      .catch(() =>
        setCodeSummary({
          total_findings: 0,
          findings_last_24h: 0,
          severity_distribution: {},
          top_finding_types: [],
        })
      );
  }, []);

  const options = useMemo(() => {
    const providers = new Set();
    const sources = new Set();
    const severities = new Set();
    const riskTypes = new Set();
    const frameworks = new Set();
    const atlasTechniques = new Set();
    const compliances = new Set();

    (logs || []).forEach((item) => {
      providers.add(item?.provider || "unknown");
      sources.add(item?.source || item?.extra_metadata?.connector_source || item?.extra_metadata?.source || "unknown");
      severities.add((item?.severity || "LOW").toUpperCase());
      riskTypes.add(item?.risk_type || item?.findings?.[0]?.risk_type || "none");
      frameworks.add(item?.findings?.[0]?.framework || "OWASP_LLM_TOP10");
      atlasTechniques.add(item?.findings?.[0]?.atlas_technique || "Unknown");
      (item?.findings?.[0]?.compliance_mappings || []).forEach((m) => {
        const key = complianceKey(m);
        if (key) compliances.add(key);
      });
    });

    return {
      providers: Array.from(providers).sort(),
      sources: Array.from(sources).sort(),
      severities: Array.from(severities).sort((a, b) => (severityRank[b] || 0) - (severityRank[a] || 0)),
      riskTypes: Array.from(riskTypes).sort(),
      frameworks: Array.from(frameworks).sort(),
      atlasTechniques: Array.from(atlasTechniques).sort(),
      compliances: Array.from(compliances).sort(),
    };
  }, [logs]);

  const rows = useMemo(() => {
    const filtered = (logs || []).filter((item) => {
      const rowRiskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
      const rowSeverity = (item?.severity || "LOW").toUpperCase();
      const rowProvider = item?.provider || "unknown";
      const rowSource = item?.source || item?.extra_metadata?.connector_source || item?.extra_metadata?.source || "unknown";
      const rowPrompt = (item?.prompt || "").toLowerCase();
      const rowFramework = item?.findings?.[0]?.framework || "OWASP_LLM_TOP10";
      const rowAtlas = item?.findings?.[0]?.atlas_technique || "Unknown";
      const rowRiskScore = Number(item?.risk_score ?? item?.findings?.[0]?.score ?? 0);
      const rowCompliances = (item?.findings?.[0]?.compliance_mappings || []).map((m) => complianceKey(m)).filter(Boolean);

      if (riskType && rowRiskType !== riskType) return false;
      if (severity && rowSeverity !== severity) return false;
      if (provider && rowProvider !== provider) return false;
      if (minRiskScore !== "" && rowRiskScore < Number(minRiskScore)) return false;
      if (maxRiskScore !== "" && rowRiskScore > Number(maxRiskScore)) return false;
      if (source && rowSource !== source) return false;
      if (framework && rowFramework !== framework) return false;
      if (atlasTechnique && rowAtlas !== atlasTechnique) return false;
      if (compliance && !rowCompliances.includes(compliance)) return false;
      if (search && !`${rowPrompt} ${String(rowProvider).toLowerCase()} ${String(rowSource).toLowerCase()}`.includes(search.toLowerCase())) return false;
      return true;
    });

    filtered.sort((a, b) => {
      if (sortBy === "severity") {
        const av = severityRank[(a?.severity || "LOW").toUpperCase()] || 0;
        const bv = severityRank[(b?.severity || "LOW").toUpperCase()] || 0;
        return sortDir === "asc" ? av - bv : bv - av;
      }
      if (sortBy === "risk_score") {
        const av = Number(a?.risk_score ?? a?.findings?.[0]?.score ?? 0);
        const bv = Number(b?.risk_score ?? b?.findings?.[0]?.score ?? 0);
        return sortDir === "asc" ? av - bv : bv - av;
      }
      const at = parseBackendTimestamp(a?.created_at || a?.timestamp)?.getTime() || 0;
      const bt = parseBackendTimestamp(b?.created_at || b?.timestamp)?.getTime() || 0;
      return sortDir === "asc" ? at - bt : bt - at;
    });

    return filtered;
  }, [logs, riskType, severity, provider, minRiskScore, maxRiskScore, source, framework, atlasTechnique, compliance, search, sortBy, sortDir]);

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Requests</h1>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-lg font-semibold text-slate-100 mb-3">AI Code Security Findings</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-3">
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">Total Findings</p>
            <p className="text-2xl font-bold text-cyan-300">{codeSummary.total_findings}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">Last 24h</p>
            <p className="text-2xl font-bold text-violet-300">{codeSummary.findings_last_24h}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">Critical</p>
            <p className="text-2xl font-bold text-rose-300">{Number(codeSummary?.severity_distribution?.CRITICAL || 0)}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">High</p>
            <p className="text-2xl font-bold text-amber-300">{Number(codeSummary?.severity_distribution?.HIGH || 0)}</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {(codeSummary?.top_finding_types || []).slice(0, 5).map((item) => (
            <button
              type="button"
              key={item.finding_type}
              onClick={() => setSearch(String(item.finding_type || ""))}
              className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-200 hover:bg-cyan-500/20 cursor-pointer"
              title="Filter request list by this finding type keyword"
            >
              {item.finding_type}: {item.count}
            </button>
          ))}
          {(codeSummary?.top_finding_types || []).length === 0 && (
            <span className="text-sm text-slate-400">No code findings yet.</span>
          )}
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-11 gap-3">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search prompt text"
            autoComplete="off"
            className="xl:col-span-2 h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <select value={riskType} onChange={(e) => setRiskType(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Risk Types</option>
            {(options.riskTypes || []).map((rt) => <option key={rt} value={rt}>{rt}</option>)}
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Severities</option>
            {(options.severities || []).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={provider} onChange={(e) => setProvider(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Providers</option>
            {(options.providers || []).map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <input
            type="number"
            min="0"
            max="100"
            value={minRiskScore}
            onChange={(e) => setMinRiskScore(e.target.value)}
            placeholder="Min Risk"
            className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <input
            type="number"
            min="0"
            max="100"
            value={maxRiskScore}
            onChange={(e) => setMaxRiskScore(e.target.value)}
            placeholder="Max Risk"
            className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <select value={source} onChange={(e) => setSource(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Sources</option>
            {(options.sources || []).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={framework} onChange={(e) => setFramework(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Frameworks</option>
            {(options.frameworks || []).map((f) => <option key={f} value={f}>{frameworkLabel(f)}</option>)}
          </select>
          <select value={atlasTechnique} onChange={(e) => setAtlasTechnique(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All ATLAS Techniques</option>
            {(options.atlasTechniques || []).map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <select value={compliance} onChange={(e) => setCompliance(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
            <option value="">All Compliance</option>
            {(options.compliances || []).map((c) => <option key={c} value={c}>{complianceLabel(c)}</option>)}
          </select>
          <div className="flex gap-2">
            <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className="w-full h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
              <option value="timestamp">Sort: Timestamp</option>
              <option value="severity">Sort: Severity</option>
              <option value="risk_score">Sort: Risk Score</option>
            </select>
            <button
              type="button"
              onClick={() => setSortDir((v) => (v === "asc" ? "desc" : "asc"))}
              title="Toggle sort direction"
              className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100 hover:border-cyan-500/60 cursor-pointer"
            >
              {sortDir === "asc" ? "Asc" : "Desc"}
            </button>
          </div>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <div className="overflow-auto">
          <table className="w-full text-sm min-w-[1160px]">
            <thead className="text-slate-400">
              <tr className="border-b border-slate-800/80">
                <th className="text-left py-2 pr-4">Prompt (input)</th>
                <th className="text-left py-2 pr-4">Risk Type</th>
                <th className="text-left py-2 pr-4">Framework</th>
                <th className="text-left py-2 pr-4">MITRE ATLAS</th>
                <th className="text-left py-2 pr-4">OWASP</th>
                <th className="text-left py-2 pr-4">Compliance</th>
                <th className="text-left py-2 pr-4">Severity</th>
                <th className="text-left py-2 pr-4">Risk Score</th>
                <th className="text-left py-2 pr-4">Action</th>
                <th className="text-left py-2 pr-4">Timestamp (IST)</th>
                <th className="text-left py-2 pr-4">Source</th>
                <th className="text-left py-2">Provider</th>
              </tr>
            </thead>
            <tbody>
              {(rows || []).map((item, idx) => {
                const status = getStatus(item);
                const rowRiskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
                const rawOwasp = item?.findings?.[0]?.owasp_category;
                const rowOwasp = !rawOwasp || String(rawOwasp).toLowerCase() === "unknown"
                  ? owaspFromRisk(rowRiskType)
                  : rawOwasp;
                const rowFramework = item?.findings?.[0]?.framework || "OWASP_LLM_TOP10";
                const rowAtlasTechnique = item?.findings?.[0]?.atlas_technique || "Unknown";
                const rowAtlasId = item?.findings?.[0]?.atlas_technique_id || "";
                const rowCompliance = item?.findings?.[0]?.compliance_mappings || [];
                const rowSeverity = (item?.severity || "LOW").toUpperCase();
                const rowRiskScore = Number(item?.risk_score ?? item?.findings?.[0]?.score ?? 0);
                const rowSource = item?.source || item?.extra_metadata?.connector_source || item?.extra_metadata?.source || "unknown";
                const ts = item?.created_at || item?.timestamp;
                return (
                  <tr
                    key={`${item?.id || "row"}-${idx}`}
                    className="border-b border-slate-800/60 hover:bg-slate-800/35 transition-colors cursor-pointer interactive-row"
                    onClick={() => navigate(`/dashboard?risk_type=${encodeURIComponent(rowRiskType)}&provider=${encodeURIComponent(item?.provider || "unknown")}&source=${encodeURIComponent(rowSource)}`)}
                    title="Click to open filtered dashboard view"
                  >
                    <td className="py-2 pr-4 text-slate-200 max-w-[520px]">
                      <div
                        className="overflow-x-auto whitespace-nowrap pr-1"
                        title={item?.prompt || "-"}
                      >
                        {item?.prompt || "-"}
                      </div>
                    </td>
                    <td
                      className="py-2 pr-4 text-cyan-300 hover:underline cursor-pointer"
                      onClick={(e) => {
                        e.stopPropagation();
                        setRiskType(rowRiskType === "none" ? "" : rowRiskType);
                      }}
                      title="Click to filter this risk type"
                    >
                      {rowRiskType === "none" ? "No Risk Detected" : rowRiskType}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${rowFramework === "OWASP_AGENTIC" ? "bg-indigo-500/15 text-indigo-300 border-indigo-500/40" : "bg-cyan-500/15 text-cyan-300 border-cyan-500/40"}`}>
                        {rowFramework === "OWASP_AGENTIC" ? "Agentic" : "LLM Top10"}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-slate-300">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setAtlasTechnique(rowAtlasTechnique);
                        }}
                        className="hover:underline cursor-pointer"
                        title={rowAtlasId || "ATLAS technique"}
                      >
                        {rowAtlasTechnique}
                      </button>
                    </td>
                    <td className="py-2 pr-4 text-slate-300">{rowOwasp}</td>
                    <td className="py-2 pr-4 text-slate-300">
                      {rowCompliance.length === 0 ? (
                        <span className="text-slate-500">-</span>
                      ) : (
                        <div className="flex flex-wrap gap-1 max-w-[260px]">
                          {rowCompliance.slice(0, 2).map((c) => {
                            const key = complianceKey(c);
                            return (
                              <span key={key} className="inline-flex items-center rounded-full border border-violet-500/40 bg-violet-500/10 px-2 py-0.5 text-[11px] text-violet-300">
                                {c?.framework}:{c?.control_id}
                              </span>
                            );
                          })}
                          {rowCompliance.length > 2 && (
                            <span className="inline-flex items-center rounded-full border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-300">
                              +{rowCompliance.length - 2}
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="py-2 pr-4">
                      <SeverityBadge severity={rowSeverity} />
                    </td>
                    <td className="py-2 pr-4 text-slate-200">{Number.isFinite(rowRiskScore) ? rowRiskScore : 0}</td>
                    <td className="py-2 pr-4">
                      <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${badgeClass(status)}`}>
                        {status}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-slate-300">{formatISTTimestamp(ts)}</td>
                    <td
                      className="py-2 pr-4 text-cyan-300 hover:underline cursor-pointer"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSource(rowSource);
                      }}
                      title="Click to filter this source"
                    >
                      {rowSource}
                    </td>
                    <td
                      className="py-2 text-slate-300 hover:underline cursor-pointer"
                      onClick={(e) => {
                        e.stopPropagation();
                        setProvider(item?.provider || "unknown");
                      }}
                      title="Click to filter this provider"
                    >
                      {item?.provider || "unknown"}
                    </td>
                  </tr>
                );
              })}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={12} className="py-6 text-center text-slate-400">No requests found</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
