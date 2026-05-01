const scoreClass = (score) => {
  if (score >= 80) return "text-rose-300 bg-rose-500/15 border-rose-500/50";
  if (score >= 60) return "text-orange-300 bg-orange-500/15 border-orange-500/50";
  if (score >= 30) return "text-amber-300 bg-amber-500/15 border-amber-500/50";
  return "text-emerald-300 bg-emerald-500/15 border-emerald-500/50";
};

const statusClass = (status) => {
  if (status === "BLOCKED") return "text-rose-300 bg-rose-500/10 border-rose-500/30";
  if (status === "WARNING") return "text-amber-300 bg-amber-500/10 border-amber-500/30";
  return "text-emerald-300 bg-emerald-500/10 border-emerald-500/30";
};

const severityClass = (severity) => {
  if (severity === "CRITICAL") return "text-rose-300";
  if (severity === "HIGH") return "text-orange-300";
  if (severity === "MEDIUM") return "text-amber-300";
  return "text-emerald-300";
};

const riskTypeLabel = (alert) => {
  const type = alert?.findings?.[0]?.risk_type || "unknown";
  if (type === "prompt_injection") return "Injection";
  if (type === "sensitive_data_exposure") return "Data Leak";
  if (type === "policy_violation") return "Policy Violation";
  if (type === "hallucination") return "Hallucination";
  if (type === "toxicity_or_harm") return "Harmful Output";
  return "Anomaly";
};

export default function AlertsPanel({ alerts, onFlag, onBlock, onInspect, fullScreen = false }) {
  const listClass = fullScreen
    ? "space-y-2 h-[calc(100vh-300px)] min-h-[520px] overflow-auto pr-1"
    : "space-y-2 max-h-80 overflow-auto pr-1";

  return (
    <div className="glass-panel bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold mb-3 text-slate-100">Live Attack Feed</h2>
      <div className={listClass}>
        {alerts.length === 0 && <p className="text-slate-400 text-sm">No active attack alerts.</p>}
        {alerts.map((a) => (
          <div
            key={a.id}
            onClick={() => onInspect?.(a)}
            title="Click to inspect this alert"
            className={`p-3 rounded-2xl bg-slate-900/80 backdrop-blur border transition ${
              ["CRITICAL", "HIGH"].includes((a.severity || "").toUpperCase())
                ? "active-threat critical-glow pulse-slow"
                : "border-slate-800 low-noise"
            } interactive-card`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-xs uppercase tracking-wide text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 rounded px-2 py-1">
                  {riskTypeLabel(a)}
                </span>
                <span className={`text-xs uppercase tracking-wide rounded px-2 py-1 border ${statusClass(a.metadata?.status || (a.metadata?.blocked ? "BLOCKED" : "SAFE"))}`}>
                  {a.metadata?.status || (a.metadata?.blocked ? "BLOCKED" : "SAFE")}
                </span>
                <span className={`text-xs uppercase tracking-wide ${severityClass(a.severity)}`}>
                  {a.severity}
                </span>
                <span className="text-xs text-slate-400">{new Date(a.created_at).toLocaleString()}</span>
              </div>
              <span className={`text-xs font-semibold border rounded px-2 py-1 ${scoreClass(a.risk_score)}`}>
                Risk {a.risk_score}
              </span>
            </div>
            <p className="text-sm text-slate-300 mt-2">
              {(a.prompt || "").slice(0, 110)}
              {(a.prompt || "").length > 110 ? "..." : ""}
            </p>
            {(a.findings || []).length > 0 && (
              <div className="mt-2 text-xs text-slate-300">
                <p className="text-slate-400 mb-1">Remediation</p>
                <p>{a.findings[0]?.remediation?.join(" | ")}</p>
              </div>
            )}
            <div className="flex gap-2 mt-3">
              <button onClick={(e) => { e.stopPropagation(); onBlock?.(a); }} className="text-xs bg-rose-600/90 hover:bg-rose-500 rounded px-3 py-1.5 font-semibold">
                Block
              </button>
              <button onClick={(e) => { e.stopPropagation(); onFlag?.(a); }} className="text-xs bg-amber-600/90 hover:bg-amber-500 rounded px-3 py-1.5 font-semibold">
                Flag
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
