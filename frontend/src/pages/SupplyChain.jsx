import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";
import SeverityBadge from "../components/SeverityBadge";

const severityClass = (sev) => {
  const s = String(sev || "LOW").toUpperCase();
  if (s === "CRITICAL") return "text-red-400";
  if (s === "HIGH") return "text-orange-400";
  if (s === "MEDIUM") return "text-yellow-300";
  return "text-emerald-400";
};

const statusClass = (status) => {
  const s = String(status || "MONITOR").toUpperCase();
  if (s === "OPEN") return "text-rose-300 border-rose-500/40 bg-rose-500/10";
  if (s === "PASS") return "text-emerald-300 border-emerald-500/40 bg-emerald-500/10";
  return "text-cyan-300 border-cyan-500/40 bg-cyan-500/10";
};

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

function vulnerabilityStatus(row) {
  const explicit = String(row?.metadata?.status || row?.status || "").toUpperCase();
  if (["OPEN", "MONITOR", "PASS"].includes(explicit)) return explicit;
  const sev = String(row?.severity || "LOW").toUpperCase();
  if (sev === "CRITICAL" || sev === "HIGH") return "OPEN";
  if (sev === "MEDIUM") return "MONITOR";
  return "PASS";
}

export default function SupplyChain({ onOpenDrilldown = () => {} }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [vulnRows, setVulnRows] = useState([]);
  const [vulnSummary, setVulnSummary] = useState({
    total_findings: 0,
    findings_last_24h: 0,
    severity_distribution: {},
    top_finding_types: [],
  });
  const [vulnSearch, setVulnSearch] = useState("");
  const [vulnSeverity, setVulnSeverity] = useState("");
  const [vulnProvider, setVulnProvider] = useState("");
  const [vulnSource, setVulnSource] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [expandedVulnRowId, setExpandedVulnRowId] = useState(null);

  const loadSupplyChain = async (forceRefresh = false) => {
    if (forceRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError("");

    try {
      const suffix = forceRefresh ? "?refresh=1" : "";
      const res = await apiFetch(`/api/supply-chain${suffix}`);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(`Failed to load supply-chain risks (${res.status})${detail ? `: ${detail}` : ""}`);
      }
      const json = await res.json();
      setData(json || null);
    } catch (e) {
      setError(e?.message || "Unable to load supply chain risk data.");
      setData(null);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadSupplyChain(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (loading) return;
    const params = new URLSearchParams();
    if (vulnSeverity) params.set("severity", vulnSeverity);
    if (vulnProvider) params.set("provider", vulnProvider);
    if (vulnSource) params.set("source", vulnSource);
    params.set("limit", "1000");
    apiFetch(`/api/code-findings?${params.toString()}`)
      .then((res) => (res.ok ? res.json() : []))
      .then((json) => setVulnRows(Array.isArray(json) ? json : []))
      .catch(() => setVulnRows([]));
  }, [loading, vulnSeverity, vulnProvider, vulnSource]);

  useEffect(() => {
    if (loading) return;
    apiFetch("/api/code-findings/summary")
      .then((res) => (res.ok ? res.json() : null))
      .then((json) =>
        setVulnSummary({
          total_findings: Number(json?.total_findings || 0),
          findings_last_24h: Number(json?.findings_last_24h || 0),
          severity_distribution: json?.severity_distribution || {},
          top_finding_types: Array.isArray(json?.top_finding_types) ? json.top_finding_types : [],
        }),
      )
      .catch(() =>
        setVulnSummary({
          total_findings: 0,
          findings_last_24h: 0,
          severity_distribution: {},
          top_finding_types: [],
        }),
      );
  }, [loading]);

  const summary = data?.summary || {};
  const findings = Array.isArray(data?.findings) ? data.findings : [];
  const scanErrors = Array.isArray(data?.scan_errors) ? data.scan_errors : [];
  const generatedAt = data?.generated_at ? new Date(data.generated_at).toLocaleString() : "N/A";
  const feedStatus = String(summary.feed_status || "unknown").toUpperCase();
  const feedStatusClass =
    feedStatus === "OK"
      ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
      : feedStatus === "PARTIAL"
        ? "text-yellow-300 border-yellow-500/40 bg-yellow-500/10"
        : feedStatus === "DISABLED"
          ? "text-rose-300 border-rose-500/40 bg-rose-500/10"
          : "text-orange-300 border-orange-500/40 bg-orange-500/10";

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      const sev = String(f?.severity || "").toUpperCase();
      const status = String(f?.status || "").toUpperCase();
      const hay = `${f?.title || ""} ${f?.category || ""} ${f?.affected_component || ""}`.toLowerCase();
      if (severityFilter && sev !== severityFilter) return false;
      if (statusFilter && status !== statusFilter) return false;
      if (search && !hay.includes(search.toLowerCase())) return false;
      return true;
    });
  }, [findings, severityFilter, statusFilter, search]);

  const vulnOptions = useMemo(() => {
    const severities = new Set();
    const providers = new Set();
    const sources = new Set();
    (vulnRows || []).forEach((r) => {
      severities.add(String(r?.severity || "LOW").toUpperCase());
      providers.add(r?.provider || "unknown");
      sources.add(r?.source || "unknown");
    });
    return {
      severities: Array.from(severities).sort(),
      providers: Array.from(providers).sort(),
      sources: Array.from(sources).sort(),
    };
  }, [vulnRows]);

  const filteredVulns = useMemo(
    () =>
      (vulnRows || []).filter((r) => {
        if (!vulnSearch) return true;
        const q = vulnSearch.toLowerCase();
        const hay = `${r?.finding_type || ""} ${r?.title || ""} ${r?.explanation || ""} ${r?.prompt || ""}`.toLowerCase();
        return hay.includes(q);
      }),
    [vulnRows, vulnSearch],
  );

  const vulnTableRows = useMemo(
    () =>
      (filteredVulns || []).map((r) => {
        const sev = String(r?.severity || "LOW").toUpperCase();
        const status = vulnerabilityStatus(r);
        const confidence = Number(r?.confidence || 0);
        const score = Math.round(confidence * 100);
        const evidenceCount = String(r?.evidence || "").trim() ? 1 : 0;
        return {
          id: r?.id,
          finding: r?.title || r?.finding_type || "Unknown finding",
          category: r?.finding_type ? `${r.finding_type} / App Vulnerability` : "App Vulnerability",
          severity: sev,
          status,
          score,
          evidence: evidenceCount,
          component: r?.endpoint || `${r?.provider || "unknown"}:${r?.source || "unknown"}`,
          lastSeen: r?.timestamp || null,
          raw: r,
        };
      }),
    [filteredVulns],
  );

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Vulnerability Findings Dashboard</h1>

      {loading && <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-slate-300">Loading supply-chain findings...</div>}
      {error && <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-rose-300">{error}</div>}

      {!loading && !error && (
        <>
          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="text-sm text-slate-300">
                Last updated: <span className="text-slate-100">{generatedAt}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${feedStatusClass}`}>
                  Feed: {feedStatus}
                </span>
                <button
                  type="button"
                  onClick={() => loadSupplyChain(true)}
                  disabled={refreshing}
                  className="rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-2 text-sm text-cyan-200 transition hover:border-cyan-400 hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {refreshing ? "Running CVE Scan..." : "Run CVE Scan"}
                </button>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-2 md:grid-cols-5 xl:grid-cols-11 gap-3">
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Overall Score</p>
              <p className="text-2xl font-bold text-cyan-300">{summary.overall_score ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Total Findings</p>
              <p className="text-2xl font-bold text-slate-100">{summary.total_findings ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Critical</p>
              <p className="text-2xl font-bold text-red-400">{summary.critical ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">High</p>
              <p className="text-2xl font-bold text-orange-400">{summary.high ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Medium</p>
              <p className="text-2xl font-bold text-yellow-300">{summary.medium ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Open</p>
              <p className="text-2xl font-bold text-rose-300">{summary.open ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Monitor</p>
              <p className="text-2xl font-bold text-cyan-300">{summary.monitor ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Pass</p>
              <p className="text-2xl font-bold text-emerald-300">{summary.pass_count ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">CVEs</p>
              <p className="text-2xl font-bold text-rose-300">{summary.cve_count ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Deps Scanned</p>
              <p className="text-2xl font-bold text-slate-100">{summary.scanned_dependencies ?? 0}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Unpinned</p>
              <p className="text-2xl font-bold text-yellow-300">{summary.unpinned_dependencies ?? 0}</p>
            </div>
          </div>

          {scanErrors.length > 0 && (
            <section className="rounded-2xl border border-yellow-500/30 bg-yellow-500/10 p-4">
              <h2 className="text-sm font-semibold text-yellow-200">Scan Errors ({scanErrors.length})</h2>
              <ul className="mt-2 space-y-1 text-xs text-yellow-100/90">
                {scanErrors.slice(0, 8).map((err, idx) => (
                  <li key={`${err}-${idx}`} className="truncate">{err}</li>
                ))}
              </ul>
            </section>
          )}

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-2 mb-3">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search findings..."
                className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              >
                <option value="">All Status</option>
                <option value="OPEN">Open</option>
                <option value="MONITOR">Monitor</option>
                <option value="PASS">Pass</option>
              </select>
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSeverityFilter("");
                  setStatusFilter("");
                }}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 hover:border-cyan-500/60"
              >
                Reset Filters
              </button>
            </div>

            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead className="text-slate-400">
                  <tr className="border-b border-slate-800">
                    <th className="py-2 text-left">Finding</th>
                    <th className="py-2 text-left">Category</th>
                    <th className="py-2 text-left">Severity</th>
                    <th className="py-2 text-left">Status</th>
                    <th className="py-2 text-left">Score</th>
                    <th className="py-2 text-left">Evidence</th>
                    <th className="py-2 text-left">Component</th>
                    <th className="py-2 text-left">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {(filtered || []).map((f, idx) => (
                    <tr
                      key={`${f.finding_id}-${idx}`}
                      className="border-t border-slate-800/80 hover:bg-slate-800/40 cursor-pointer"
                      onClick={() => {
                        const rows = (f.evidence_samples || []).map((e) => ({
                          prompt: e.prompt,
                          risk_type: e.risk_type,
                          severity: e.severity,
                          timestamp: e.timestamp,
                          remediation: f.remediation,
                        }));
                        onOpenDrilldown(`Supply Chain: ${f.title}`, rows);
                      }}
                    >
                      <td className="py-2 text-slate-100">{f.title}</td>
                      <td className="py-2 text-slate-300">{f.category}</td>
                      <td className={`py-2 font-semibold ${severityClass(f.severity)}`}>{f.severity}</td>
                      <td className="py-2">
                        <span className={`rounded-md border px-2 py-0.5 text-xs ${statusClass(f.status)}`}>{f.status}</span>
                      </td>
                      <td className="py-2 text-cyan-300">{f.score}</td>
                      <td className="py-2 text-slate-200">{f.evidence_count}</td>
                      <td className="py-2 text-slate-300">{f.affected_component}</td>
                      <td className="py-2 text-slate-400">
                        {f.last_seen ? new Date(f.last_seen).toLocaleString() : "N/A"}
                      </td>
                    </tr>
                  ))}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={8} className="py-4 text-center text-slate-400">No findings match current filters.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="flex items-center justify-between gap-2 mb-3">
              <h2 className="text-lg font-semibold text-slate-100">Vulnerability Findings</h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-3">
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs uppercase text-slate-400">Total Findings</p>
                <p className="text-2xl font-bold text-cyan-300">{vulnSummary.total_findings}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs uppercase text-slate-400">Last 24h</p>
                <p className="text-2xl font-bold text-violet-300">{vulnSummary.findings_last_24h}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs uppercase text-slate-400">Critical</p>
                <p className="text-2xl font-bold text-rose-300">{Number(vulnSummary?.severity_distribution?.CRITICAL || 0)}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs uppercase text-slate-400">High</p>
                <p className="text-2xl font-bold text-amber-300">{Number(vulnSummary?.severity_distribution?.HIGH || 0)}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-2 mb-3">
              <input
                value={vulnSearch}
                onChange={(e) => setVulnSearch(e.target.value)}
                placeholder="Search finding/title/prompt"
                className="xl:col-span-2 rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100"
              />
              <select value={vulnSeverity} onChange={(e) => setVulnSeverity(e.target.value)} className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100">
                <option value="">All Severities</option>
                {vulnOptions.severities.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={vulnProvider} onChange={(e) => setVulnProvider(e.target.value)} className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100">
                <option value="">All Providers</option>
                {vulnOptions.providers.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
              <select value={vulnSource} onChange={(e) => setVulnSource(e.target.value)} className="rounded-lg bg-slate-900 border border-slate-700 p-2 text-slate-100">
                <option value="">All Sources</option>
                {vulnOptions.sources.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>

            <div className="mb-3 flex flex-wrap gap-2">
              {(vulnSummary?.top_finding_types || []).slice(0, 6).map((item) => (
                <button
                  key={item.finding_type}
                  type="button"
                  onClick={() => setVulnSearch(String(item.finding_type || ""))}
                  className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-200 hover:bg-cyan-500/20"
                >
                  {item.finding_type}: {item.count}
                </button>
              ))}
            </div>

            <div className="overflow-auto">
              <table className="w-full text-sm min-w-[980px]">
                <thead className="text-slate-400">
                  <tr className="border-b border-slate-800/80">
                    <th className="text-left py-2 pr-4">Finding</th>
                    <th className="text-left py-2 pr-4">Category</th>
                    <th className="text-left py-2 pr-4">Severity</th>
                    <th className="text-left py-2 pr-4">Status</th>
                    <th className="text-left py-2 pr-4">Score</th>
                    <th className="text-left py-2 pr-4">Evidence</th>
                    <th className="text-left py-2 pr-4">Component</th>
                    <th className="text-left py-2">Last Seen</th>
                    <th className="text-left py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(vulnTableRows || []).map((r) => (
                    <>
                      <tr
                        key={r.id}
                        className="border-t border-slate-800/80 hover:bg-slate-800/40"
                      >
                        <td className="py-2 pr-4 text-slate-100">{r.finding}</td>
                        <td className="py-2 pr-4 text-slate-300">{r.category}</td>
                        <td className={`py-2 pr-4 font-semibold ${severityClass(r.severity)}`}>{r.severity}</td>
                        <td className="py-2 pr-4">
                          <span className={`rounded-md border px-2 py-0.5 text-xs ${statusClass(r.status)}`}>{r.status}</span>
                        </td>
                        <td className="py-2 pr-4 text-cyan-300">{r.score}</td>
                        <td className="py-2 pr-4 text-slate-200">{r.evidence}</td>
                        <td className="py-2 pr-4 text-slate-300">{r.component}</td>
                        <td className="py-2 text-slate-400">{r.lastSeen ? tsLabel(r.lastSeen) : "N/A"}</td>
                        <td className="py-2 whitespace-nowrap">
                          <div className="flex gap-2">
                            <button
                              type="button"
                              onClick={() => setExpandedVulnRowId((prev) => (prev === r.id ? null : r.id))}
                              className="rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-xs text-cyan-200 hover:bg-cyan-500/20"
                              title="Show exact prompt text"
                            >
                              {expandedVulnRowId === r.id ? "Hide Prompt" : "Exact Prompt"}
                            </button>
                            <button
                              type="button"
                              onClick={() => setSelectedVuln(r.raw)}
                              className="rounded-md border border-slate-600 bg-slate-900/70 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500/50"
                            >
                              Details
                            </button>
                          </div>
                        </td>
                      </tr>
                      {expandedVulnRowId === r.id && (
                        <tr className="border-t border-slate-800/60 bg-slate-900/40">
                          <td colSpan={9} className="py-2">
                            <div className="rounded-md border border-slate-700 bg-slate-950/60 p-3">
                              <p className="text-[11px] uppercase tracking-wide text-slate-400 mb-2">Exact Prompt</p>
                              <pre className="text-xs text-slate-200 whitespace-pre-wrap break-words font-mono">
                                {String(r.raw?.prompt || "-")}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                  {vulnTableRows.length === 0 && (
                    <tr>
                      <td colSpan={9} className="py-4 text-center text-slate-400">No vulnerability findings match current filters.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {selectedVuln && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm p-4 flex items-center justify-center">
          <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-slate-100">{selectedVuln.title}</h3>
                <p className="text-xs text-slate-400 mt-1">
                  {selectedVuln.finding_type} | {selectedVuln.provider} | {selectedVuln.source} | {tsLabel(selectedVuln.timestamp)} IST
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedVuln(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-sm text-slate-200 hover:border-cyan-500/60"
              >
                Close
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Severity</p>
                <div className="mt-1"><SeverityBadge severity={(selectedVuln.severity || "LOW").toUpperCase()} /></div>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Confidence</p>
                <p className="text-base font-semibold text-indigo-300">{Number(selectedVuln.confidence || 0).toFixed(2)}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Endpoint</p>
                <p className="text-base font-semibold text-slate-200">{selectedVuln.endpoint || "-"}</p>
              </div>
            </div>
            <div className="space-y-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Explanation</p>
                <p className="text-sm text-slate-200 mt-1">{selectedVuln.explanation || "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Evidence</p>
                <p className="text-sm text-slate-200 mt-1 break-words">{selectedVuln.evidence || "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Remediation</p>
                <p className="text-sm text-emerald-300 mt-1">{selectedVuln.remediation || "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Prompt Context</p>
                <p className="text-sm text-slate-200 mt-1 break-words">{selectedVuln.prompt || "-"}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
