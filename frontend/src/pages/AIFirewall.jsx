import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";
import SeverityBadge from "../components/SeverityBadge";

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

function isBlocked(item) {
  const status = String(item?.metadata?.status || item?.extra_metadata?.status || "").toUpperCase();
  if (status === "BLOCKED") return true;
  return item?.blocked === true || item?.metadata?.blocked === true || item?.extra_metadata?.blocked === true;
}

function isWarning(item) {
  const status = String(item?.metadata?.status || item?.extra_metadata?.status || "").toUpperCase();
  return status === "WARNING";
}

function riskTypeOf(item) {
  return item?.risk_type || item?.findings?.[0]?.risk_type || "unknown";
}

function decisionOf(item) {
  if (isBlocked(item)) return "BLOCKED";
  if (isWarning(item)) return "WARNING";
  return "ALLOWED";
}

function priorityScore(item, globalBlockScore = 80) {
  const score = Number(item?.risk_score || 0);
  const sev = String(item?.severity || "LOW").toUpperCase();
  const decision = decisionOf(item);
  let p = score;
  if (decision === "ALLOWED" && score >= globalBlockScore) p += 30; // risky allow-bypass candidate
  if (decision === "WARNING") p += 15;
  if (sev === "CRITICAL") p += 12;
  if (sev === "HIGH") p += 6;
  return p;
}

export default function AIFirewall() {
  const [policy, setPolicy] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [selectedBlocked, setSelectedBlocked] = useState(null);
  const [actionBusyId, setActionBusyId] = useState(null);
  const [actionFeedback, setActionFeedback] = useState("");
  const [windowMinutes, setWindowMinutes] = useState(60);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const [policyRes, logsRes] = await Promise.all([
          apiFetch("/api/policy/control-plane"),
          apiFetch("/api/logs?limit=1000"),
        ]);
        const policyJson = policyRes.ok ? await policyRes.json() : null;
        const logsJson = logsRes.ok ? await logsRes.json() : [];
        setPolicy(policyJson || null);
        setLogs(Array.isArray(logsJson) ? logsJson : []);
      } catch (e) {
        setError(e?.message || "Failed to load AI Firewall telemetry.");
        setPolicy(null);
        setLogs([]);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const refreshData = async () => {
    const [policyRes, logsRes] = await Promise.all([
      apiFetch("/api/policy/control-plane"),
      apiFetch("/api/logs?limit=1000"),
    ]);
    const policyJson = policyRes.ok ? await policyRes.json() : null;
    const logsJson = logsRes.ok ? await logsRes.json() : [];
    setPolicy(policyJson || null);
    setLogs(Array.isArray(logsJson) ? logsJson : []);
  };

  const applyAnalystAction = async (logId, action) => {
    if (!logId || !["BLOCK", "FLAG"].includes(action)) return;
    setActionBusyId(logId);
    setActionFeedback("");
    try {
      const res = await apiFetch(`/api/logs/${logId}/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, note: `Analyst action from AI Firewall: ${action}` }),
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(`Action failed (${res.status})${detail ? `: ${detail}` : ""}`);
      }
      setActionFeedback(`Action applied: ${action} on log ${logId}`);
      await refreshData();
    } catch (e) {
      setActionFeedback(e?.message || "Failed to apply analyst action.");
    } finally {
      setActionBusyId(null);
    }
  };

  const options = useMemo(() => {
    const sources = new Set();
    const providers = new Set();
    (logs || []).forEach((item) => {
      sources.add(item?.source || item?.extra_metadata?.source || "unknown");
      providers.add(item?.provider || "unknown");
    });
    return {
      sources: Array.from(sources).sort(),
      providers: Array.from(providers).sort(),
    };
  }, [logs]);

  const scopedLogs = useMemo(
    () =>
      (logs || []).filter((item) => {
        const src = item?.source || item?.extra_metadata?.source || "unknown";
        const provider = item?.provider || "unknown";
        if (sourceFilter && src !== sourceFilter) return false;
        if (providerFilter && provider !== providerFilter) return false;
        return true;
      }),
    [logs, sourceFilter, providerFilter],
  );

  const blockedLogs = useMemo(() => (scopedLogs || []).filter((item) => isBlocked(item)), [scopedLogs]);
  const warningLogs = useMemo(() => (scopedLogs || []).filter((item) => isWarning(item)), [scopedLogs]);
  const globalBlockScore = Number(policy?.thresholds?.global_block_score ?? 80);
  const riskyAllowedLogs = useMemo(
    () => (scopedLogs || []).filter((item) => decisionOf(item) === "ALLOWED" && Number(item?.risk_score || 0) >= globalBlockScore),
    [scopedLogs, globalBlockScore],
  );
  const allowLogs = Math.max(0, scopedLogs.length - blockedLogs.length - warningLogs.length);
  const blockRate = scopedLogs.length ? Math.round((blockedLogs.length / scopedLogs.length) * 100) : 0;

  const blockedByRisk = useMemo(() => {
    const acc = {};
    (blockedLogs || []).forEach((item) => {
      const rt = item?.risk_type || item?.findings?.[0]?.risk_type || "unknown";
      acc[rt] = (acc[rt] || 0) + 1;
    });
    return Object.entries(acc)
      .map(([risk_type, count]) => ({ risk_type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [blockedLogs]);

  const recentBlocked = useMemo(
    () =>
      (blockedLogs || [])
        .slice(0, 12)
        .map((item, idx) => ({
          id: item?.id || idx,
          log_id: item?.id || null,
          prompt: item?.prompt || "",
          risk_type: riskTypeOf(item),
          severity: (item?.severity || "LOW").toUpperCase(),
          risk_score: Number(item?.risk_score || 0),
          source: item?.source || item?.extra_metadata?.source || "unknown",
          provider: item?.provider || "unknown",
          timestamp: item?.created_at || item?.timestamp,
          reason: item?.findings?.[0]?.explanation || "Blocked by policy decision engine.",
          remediation:
            item?.findings?.[0]?.remediation?.join("; ") ||
            "Apply stronger prompt controls, least privilege, and escalation review.",
        })),
    [blockedLogs],
  );

  const actionQueue = useMemo(
    () =>
      (scopedLogs || [])
        .filter((item) => {
          const decision = decisionOf(item);
          const score = Number(item?.risk_score || 0);
          return decision === "BLOCKED" || decision === "WARNING" || score >= globalBlockScore;
        })
        .map((item, idx) => {
          const decision = decisionOf(item);
          const score = Number(item?.risk_score || 0);
          const pScore = priorityScore(item, globalBlockScore);
          let priority = "P3";
          if (pScore >= 105) priority = "P1";
          else if (pScore >= 85) priority = "P2";
          return {
            id: item?.id || idx,
            log_id: item?.id || null,
            prompt: item?.prompt || "",
            risk_type: riskTypeOf(item),
            severity: (item?.severity || "LOW").toUpperCase(),
            risk_score: score,
            source: item?.source || item?.extra_metadata?.source || "unknown",
            provider: item?.provider || "unknown",
            timestamp: item?.created_at || item?.timestamp,
            decision,
            priority,
            priority_score: pScore,
            reason: item?.findings?.[0]?.explanation || "Firewall action required.",
            remediation: item?.findings?.[0]?.remediation?.join("; ") || "Apply containment and escalate.",
          };
        })
        .sort((a, b) => b.priority_score - a.priority_score)
        .slice(0, 20),
    [scopedLogs, globalBlockScore],
  );

  const sourceQuarantineCandidates = useMemo(() => {
    const stats = {};
    (scopedLogs || []).forEach((item) => {
      const src = item?.source || item?.extra_metadata?.source || "unknown";
      if (!stats[src]) stats[src] = { source: src, total: 0, blocked: 0, warnings: 0, avgRiskTotal: 0 };
      stats[src].total += 1;
      stats[src].blocked += isBlocked(item) ? 1 : 0;
      stats[src].warnings += isWarning(item) ? 1 : 0;
      stats[src].avgRiskTotal += Number(item?.risk_score || 0);
    });
    return Object.values(stats)
      .map((s) => ({
        ...s,
        avgRisk: s.total ? Number((s.avgRiskTotal / s.total).toFixed(1)) : 0,
        blockRate: s.total ? Math.round((s.blocked / s.total) * 100) : 0,
      }))
      .filter((s) => s.total >= 3 && (s.blockRate >= 40 || s.avgRisk >= 65))
      .sort((a, b) => b.blockRate - a.blockRate || b.avgRisk - a.avgRisk)
      .slice(0, 8);
  }, [scopedLogs]);

  const decisionMatrix = useMemo(() => {
    const matrix = {};
    (scopedLogs || []).forEach((item) => {
      const rt = riskTypeOf(item);
      if (!matrix[rt]) matrix[rt] = { risk_type: rt, BLOCKED: 0, WARNING: 0, ALLOWED: 0, total: 0, avg_score: 0 };
      const decision = decisionOf(item);
      matrix[rt][decision] += 1;
      matrix[rt].total += 1;
      matrix[rt].avg_score += Number(item?.risk_score || 0);
    });
    return Object.values(matrix)
      .map((r) => ({
        ...r,
        avg_score: r.total ? Number((r.avg_score / r.total).toFixed(1)) : 0,
        block_rate: r.total ? Math.round((r.BLOCKED / r.total) * 100) : 0,
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 10);
  }, [scopedLogs]);

  const burstSignals = useMemo(() => {
    const now = Date.now();
    const winMs = Math.max(5, Number(windowMinutes || 60)) * 60 * 1000;
    const currentStart = now - winMs;
    const previousStart = now - winMs * 2;

    const currentCounts = {};
    const previousCounts = {};

    (scopedLogs || []).forEach((item) => {
      const t = new Date(item?.created_at || item?.timestamp || 0).getTime();
      if (!t || Number.isNaN(t)) return;
      const rt = riskTypeOf(item);
      if (t >= currentStart) currentCounts[rt] = (currentCounts[rt] || 0) + 1;
      else if (t >= previousStart && t < currentStart) previousCounts[rt] = (previousCounts[rt] || 0) + 1;
    });

    const keys = Array.from(new Set([...Object.keys(currentCounts), ...Object.keys(previousCounts)]));
    return keys
      .map((risk_type) => {
        const current = Number(currentCounts[risk_type] || 0);
        const previous = Number(previousCounts[risk_type] || 0);
        const delta = current - previous;
        const ratio = previous === 0 ? (current > 0 ? 999 : 1) : current / previous;
        return {
          risk_type,
          current,
          previous,
          delta,
          ratio: Number.isFinite(ratio) ? Number(ratio.toFixed(2)) : 999,
        };
      })
      .filter((r) => r.current >= 2 && (r.delta >= 2 || r.ratio >= 1.8))
      .sort((a, b) => b.delta - a.delta || b.ratio - a.ratio)
      .slice(0, 8);
  }, [scopedLogs, windowMinutes]);

  const exportQueueJson = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      policy_version: policy?.policy_version || "unknown",
      scope: { source: sourceFilter || "all", provider: providerFilter || "all" },
      queue: actionQueue,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ai-firewall-action-queue.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">AI Firewall</h1>

      {loading && <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-slate-300">Loading firewall policy and telemetry...</div>}
      {error && <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-rose-300">{error}</div>}

      {!loading && !error && (
        <>
          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm text-slate-300">
                  Policy Version: <span className="text-cyan-300 font-semibold">{policy?.policy_version || "N/A"}</span>
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  {policy?.app_name || "AI Security Monitoring Tool"} | {policy?.environment || "unknown"}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs ${policy?.mirror_ingest_enabled ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10" : "text-slate-300 border-slate-600 bg-slate-800/60"}`}>
                  Mirror Ingest: {policy?.mirror_ingest_enabled ? "ON" : "OFF"}
                </span>
                <span className={`rounded-md border px-2 py-1 text-xs ${policy?.threat_intel_enabled ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10" : "text-slate-300 border-slate-600 bg-slate-800/60"}`}>
                  Threat Intel: {policy?.threat_intel_enabled ? "ON" : "OFF"}
                </span>
                <span className={`rounded-md border px-2 py-1 text-xs ${policy?.supply_chain_scan_enabled ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10" : "text-slate-300 border-slate-600 bg-slate-800/60"}`}>
                  Supply Chain Scan: {policy?.supply_chain_scan_enabled ? "ON" : "OFF"}
                </span>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Total Evaluated</p>
              <p className="text-2xl font-bold text-slate-100">{scopedLogs.length}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Blocked</p>
              <p className="text-2xl font-bold text-rose-300">{blockedLogs.length}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Warnings</p>
              <p className="text-2xl font-bold text-amber-300">{warningLogs.length}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Allowed</p>
              <p className="text-2xl font-bold text-emerald-300">{allowLogs}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Risky Allowed</p>
              <p className="text-2xl font-bold text-fuchsia-300">{riskyAllowedLogs.length}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-white/5 backdrop-blur-xl p-3">
              <p className="text-xs uppercase text-slate-400">Block Rate</p>
              <p className="text-2xl font-bold text-cyan-300">{blockRate}%</p>
            </div>
          </div>
          {actionFeedback && (
            <div className="rounded-xl border border-cyan-500/40 bg-cyan-500/10 p-3 text-sm text-cyan-200">
              {actionFeedback}
            </div>
          )}

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Firewall Policy Thresholds</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs text-slate-400">Prompt Injection Block</p>
                <p className="text-xl font-semibold text-rose-300">{policy?.thresholds?.prompt_injection_block_score ?? "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs text-slate-400">Indirect Injection Block</p>
                <p className="text-xl font-semibold text-rose-300">{policy?.thresholds?.indirect_injection_block_score ?? "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs text-slate-400">Warning Score</p>
                <p className="text-xl font-semibold text-amber-300">{policy?.thresholds?.warning_score ?? "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs text-slate-400">Global Block Score</p>
                <p className="text-xl font-semibold text-rose-300">{policy?.thresholds?.global_block_score ?? "-"}</p>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs uppercase text-slate-400 mb-2">Hard Block Risk Types</p>
                <div className="flex flex-wrap gap-2">
                  {(policy?.hard_block_risk_types || []).map((item) => (
                    <span key={item} className="rounded-full border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-xs text-rose-200">{item}</span>
                  ))}
                  {(policy?.hard_block_risk_types || []).length === 0 && <span className="text-xs text-slate-500">No explicit hard-block list</span>}
                </div>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
                <p className="text-xs uppercase text-slate-400 mb-2">Strict Prompt Attack Types</p>
                <div className="flex flex-wrap gap-2">
                  {(policy?.strict_prompt_attack_types || []).map((item) => (
                    <span key={item} className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-200">{item}</span>
                  ))}
                  {(policy?.strict_prompt_attack_types || []).length === 0 && <span className="text-xs text-slate-500">No strict prompt attack list</span>}
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2 mb-3">
              <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
                <option value="">All Sources</option>
                {options.sources.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)} className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-100">
                <option value="">All Providers</option>
                {options.providers.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
              <button
                type="button"
                onClick={() => {
                  setSourceFilter("");
                  setProviderFilter("");
                }}
                className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-200 hover:border-cyan-500/60"
              >
                Reset Scope
              </button>
              <div className="h-11 rounded-lg border border-slate-700 bg-slate-900/60 px-3 text-sm text-slate-400 flex items-center">
                Decision telemetry: {scopedLogs.length} requests
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-100 mb-2">Top Blocked Risk Types</h3>
                <div className="space-y-2">
                  {blockedByRisk.map((row) => (
                    <div key={row.risk_type} className="rounded-lg border border-slate-700 bg-slate-900/50 p-2 flex items-center justify-between">
                      <span className="text-cyan-300 text-sm">{row.risk_type}</span>
                      <span className="text-rose-300 text-sm font-semibold">{row.count}</span>
                    </div>
                  ))}
                  {blockedByRisk.length === 0 && <p className="text-sm text-slate-400">No blocked risk telemetry in current scope.</p>}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-100 mb-2">Recent Blocked Requests</h3>
                <div className="space-y-2">
                  {recentBlocked.map((row) => (
                    <button
                      key={row.id}
                      type="button"
                      onClick={() => setSelectedBlocked(row)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900/50 p-2 text-left hover:border-cyan-500/50"
                    >
                      <p className="text-sm text-slate-100 truncate">{row.prompt || "-"}</p>
                      <p className="text-xs text-slate-400 mt-1">{row.risk_type} | {row.source} | {row.provider}</p>
                    </button>
                  ))}
                  {recentBlocked.length === 0 && <p className="text-sm text-slate-400">No blocked requests found in current scope.</p>}
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Analyst Action Queue</h2>
            <div className="mb-3 flex justify-end">
              <button
                type="button"
                onClick={exportQueueJson}
                className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-slate-200 hover:border-cyan-500/60"
              >
                Export Queue JSON
              </button>
            </div>
            <div className="overflow-auto">
              <table className="w-full text-sm min-w-[1100px]">
                <thead className="text-slate-400">
                  <tr className="border-b border-slate-800/80">
                    <th className="text-left py-2 pr-4">Priority</th>
                    <th className="text-left py-2 pr-4">Risk Type</th>
                    <th className="text-left py-2 pr-4">Decision</th>
                    <th className="text-left py-2 pr-4">Severity</th>
                    <th className="text-left py-2 pr-4">Risk</th>
                    <th className="text-left py-2 pr-4">Source</th>
                    <th className="text-left py-2 pr-4">Provider</th>
                    <th className="text-left py-2 pr-4">Timestamp</th>
                    <th className="text-left py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {actionQueue.map((row) => (
                    <tr key={row.id} className="border-t border-slate-800/80 hover:bg-slate-800/40">
                      <td className={`py-2 pr-4 font-semibold ${row.priority === "P1" ? "text-rose-300" : row.priority === "P2" ? "text-amber-300" : "text-slate-300"}`}>{row.priority}</td>
                      <td className="py-2 pr-4 text-cyan-300">{row.risk_type}</td>
                      <td className="py-2 pr-4">
                        <span className={`rounded-md border px-2 py-0.5 text-xs ${row.decision === "BLOCKED" ? "text-rose-300 border-rose-500/40 bg-rose-500/10" : row.decision === "WARNING" ? "text-amber-300 border-amber-500/40 bg-amber-500/10" : "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"}`}>
                          {row.decision}
                        </span>
                      </td>
                      <td className="py-2 pr-4"><SeverityBadge severity={row.severity} /></td>
                      <td className="py-2 pr-4 text-rose-300 font-semibold">{row.risk_score}</td>
                      <td className="py-2 pr-4 text-slate-300">{row.source}</td>
                      <td className="py-2 pr-4 text-slate-300">{row.provider}</td>
                      <td className="py-2 pr-4 text-slate-400">{tsLabel(row.timestamp)}</td>
                      <td className="py-2 whitespace-nowrap">
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => setSelectedBlocked(row)}
                            className="rounded-md border border-slate-600 bg-slate-900/70 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500/50"
                          >
                            Details
                          </button>
                          <button
                            type="button"
                            disabled={!row.log_id || actionBusyId === row.log_id}
                            onClick={() => applyAnalystAction(row.log_id, "FLAG")}
                            className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-200 disabled:opacity-50"
                          >
                            Flag
                          </button>
                          <button
                            type="button"
                            disabled={!row.log_id || actionBusyId === row.log_id}
                            onClick={() => applyAnalystAction(row.log_id, "BLOCK")}
                            className="rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-xs text-rose-200 disabled:opacity-50"
                          >
                            Block
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {actionQueue.length === 0 && (
                    <tr>
                      <td colSpan={9} className="py-4 text-center text-slate-400">No queue items in current scope.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h2 className="text-lg font-semibold text-slate-100">Burst & Drift Signals</h2>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Window</span>
                <select
                  value={windowMinutes}
                  onChange={(e) => setWindowMinutes(Number(e.target.value))}
                  className="h-9 rounded-lg border border-slate-700 bg-slate-900/60 px-2 text-xs text-slate-100"
                >
                  <option value={30}>30m</option>
                  <option value={60}>60m</option>
                  <option value={120}>120m</option>
                  <option value={240}>240m</option>
                </select>
              </div>
            </div>
            <div className="space-y-2">
              {burstSignals.map((row) => (
                <div key={`burst-${row.risk_type}`} className="rounded-lg border border-slate-700 bg-slate-900/50 p-2 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-cyan-300 text-sm">{row.risk_type}</span>
                  <span className="text-xs text-slate-300">current: {row.current}</span>
                  <span className="text-xs text-slate-300">previous: {row.previous}</span>
                  <span className="text-xs text-rose-300">delta: +{row.delta}</span>
                  <span className="text-xs text-amber-300">ratio: {row.ratio}x</span>
                </div>
              ))}
              {burstSignals.length === 0 && <p className="text-sm text-slate-400">No significant burst/drift signals for selected window.</p>}
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Decision Matrix by Risk Type</h2>
            <div className="overflow-auto">
              <table className="w-full text-sm min-w-[900px]">
                <thead className="text-slate-400">
                  <tr className="border-b border-slate-800/80">
                    <th className="text-left py-2 pr-4">Risk Type</th>
                    <th className="text-left py-2 pr-4">Blocked</th>
                    <th className="text-left py-2 pr-4">Warning</th>
                    <th className="text-left py-2 pr-4">Allowed</th>
                    <th className="text-left py-2 pr-4">Total</th>
                    <th className="text-left py-2 pr-4">Block Rate</th>
                    <th className="text-left py-2">Avg Score</th>
                  </tr>
                </thead>
                <tbody>
                  {decisionMatrix.map((row) => (
                    <tr key={`mx-${row.risk_type}`} className="border-t border-slate-800/80 hover:bg-slate-800/35">
                      <td className="py-2 pr-4 text-cyan-300">{row.risk_type}</td>
                      <td className="py-2 pr-4 text-rose-300 font-semibold">{row.BLOCKED}</td>
                      <td className="py-2 pr-4 text-amber-300 font-semibold">{row.WARNING}</td>
                      <td className="py-2 pr-4 text-emerald-300 font-semibold">{row.ALLOWED}</td>
                      <td className="py-2 pr-4 text-slate-200">{row.total}</td>
                      <td className="py-2 pr-4 text-rose-300">{row.block_rate}%</td>
                      <td className="py-2 text-slate-200">{row.avg_score}</td>
                    </tr>
                  ))}
                  {decisionMatrix.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-4 text-center text-slate-400">No decision matrix data in current scope.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Risky Allowed Candidates</h2>
            <div className="overflow-auto">
              <table className="w-full text-sm min-w-[1000px]">
                <thead className="text-slate-400">
                  <tr className="border-b border-slate-800/80">
                    <th className="text-left py-2 pr-4">Risk Type</th>
                    <th className="text-left py-2 pr-4">Severity</th>
                    <th className="text-left py-2 pr-4">Risk</th>
                    <th className="text-left py-2 pr-4">Source</th>
                    <th className="text-left py-2 pr-4">Provider</th>
                    <th className="text-left py-2 pr-4">Timestamp</th>
                    <th className="text-left py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {riskyAllowedLogs.slice(0, 20).map((item, idx) => {
                    const rid = item?.id || idx;
                    return (
                      <tr key={`ra-${rid}`} className="border-t border-slate-800/80 hover:bg-slate-800/35">
                        <td className="py-2 pr-4 text-cyan-300">{riskTypeOf(item)}</td>
                        <td className="py-2 pr-4"><SeverityBadge severity={(item?.severity || "LOW").toUpperCase()} /></td>
                        <td className="py-2 pr-4 text-rose-300 font-semibold">{Number(item?.risk_score || 0)}</td>
                        <td className="py-2 pr-4 text-slate-300">{item?.source || item?.extra_metadata?.source || "unknown"}</td>
                        <td className="py-2 pr-4 text-slate-300">{item?.provider || "unknown"}</td>
                        <td className="py-2 pr-4 text-slate-400">{tsLabel(item?.created_at || item?.timestamp)}</td>
                        <td className="py-2">
                          <button
                            type="button"
                            disabled={!item?.id || actionBusyId === item.id}
                            onClick={() => applyAnalystAction(item.id, "BLOCK")}
                            className="rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-xs text-rose-200 disabled:opacity-50"
                          >
                            Force Block
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {riskyAllowedLogs.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-4 text-center text-slate-400">No risky-allowed candidates in current scope.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Source Quarantine Candidates</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
              {sourceQuarantineCandidates.map((row) => (
                <button
                  key={row.source}
                  type="button"
                  onClick={() => setSourceFilter(row.source)}
                  className="rounded-xl border border-slate-700 bg-slate-900/50 p-3 text-left hover:border-cyan-500/50"
                  title="Scope firewall view to this source"
                >
                  <p className="text-sm text-cyan-300 font-semibold">{row.source}</p>
                  <p className="text-xs text-slate-400 mt-1">Total: {row.total} | Blocked: {row.blocked} | Warnings: {row.warnings}</p>
                  <p className="text-xs text-rose-300 mt-1">Block Rate: {row.blockRate}%</p>
                  <p className="text-xs text-amber-300">Avg Risk: {row.avgRisk}</p>
                </button>
              ))}
              {sourceQuarantineCandidates.length === 0 && (
                <p className="text-sm text-slate-400">No high-risk source candidates in current scope.</p>
              )}
            </div>
          </section>
        </>
      )}

      {selectedBlocked && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm p-4 flex items-center justify-center">
          <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-slate-100">Blocked Request Detail</h3>
                <p className="text-xs text-slate-400 mt-1">{selectedBlocked.risk_type} | {selectedBlocked.source} | {selectedBlocked.provider} | {tsLabel(selectedBlocked.timestamp)} IST</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedBlocked(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-sm text-slate-200 hover:border-cyan-500/60"
              >
                Close
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Severity</p>
                <div className="mt-1"><SeverityBadge severity={selectedBlocked.severity} /></div>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className="text-base font-semibold text-rose-300">{selectedBlocked.risk_score}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Decision</p>
                <p className="text-base font-semibold text-rose-300">BLOCKED</p>
              </div>
            </div>
            <div className="space-y-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Prompt</p>
                <p className="text-sm text-slate-200 mt-1 break-words">{selectedBlocked.prompt || "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Policy Reason</p>
                <p className="text-sm text-slate-200 mt-1">{selectedBlocked.reason}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Recommended Remediation</p>
                <p className="text-sm text-emerald-300 mt-1">{selectedBlocked.remediation}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
