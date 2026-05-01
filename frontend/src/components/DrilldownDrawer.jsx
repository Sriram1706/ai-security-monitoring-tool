import { getThreatExplanation } from "../lib/threatExplain";

export default function DrilldownDrawer({ open, title = "Investigation", rows = [], onClose }) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <button
        type="button"
        className="absolute inset-0 bg-slate-950/60"
        onClick={onClose}
        aria-label="Close investigation drawer"
      />
      <aside className="absolute right-0 top-0 h-full w-full max-w-xl border-l border-slate-800 bg-slate-950/95 backdrop-blur-xl shadow-[0_0_40px_rgba(56,189,248,0.18)] p-4 overflow-auto">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
          <button onClick={onClose} className="text-sm text-slate-300 hover:text-white">Close</button>
        </div>

        <div className="space-y-2">
          {(rows || []).map((r, idx) => (
            <div key={idx} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              {(() => {
                const riskType = r?.risk_type || r?.type || "unknown";
                const ai = getThreatExplanation(riskType);
                return (
                  <>
              <p className="text-sm text-slate-100">{(r.prompt || "").slice(0, 220) || "-"}</p>
              <div className="mt-2 flex flex-wrap gap-2 text-xs">
                <span className="rounded px-2 py-1 border border-slate-700 text-cyan-300">{riskType}</span>
                <span className="rounded px-2 py-1 border border-slate-700 text-slate-300">{r.severity || "LOW"}</span>
                <span className="rounded px-2 py-1 border border-slate-700 text-slate-300">{r.timestamp ? new Date(r.timestamp).toLocaleString() : "-"}</span>
              </div>
              <p className="mt-2 text-xs text-slate-300"><span className="text-slate-400">What happened:</span> {ai.what_happened}</p>
              <p className="mt-1 text-xs text-slate-300"><span className="text-slate-400">Why risky:</span> {ai.why_risky}</p>
              <p className="mt-1 text-xs text-slate-300"><span className="text-slate-400">Impact:</span> {ai.impact}</p>
              <p className="mt-2 text-xs text-cyan-300">Recommended action: {ai.recommended_action}</p>
              <p className="mt-2 text-xs text-cyan-300">Remediation: {r.remediation || "Investigate and apply guardrails."}</p>
                  </>
                );
              })()}
            </div>
          ))}
          {(rows || []).length === 0 && <p className="text-sm text-slate-400">No records found.</p>}
        </div>
      </aside>
    </div>
  );
}
