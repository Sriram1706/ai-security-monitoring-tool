export default function ThreatDetailModal({ threat, onClose }) {
  if (!threat) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-3xl rounded-xl border border-slate-700 bg-slate-900 p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xl font-semibold text-slate-100">Threat Focus Mode</h3>
          <button onClick={onClose} className="text-slate-300 hover:text-white">Close</button>
        </div>
        <div className="space-y-3 text-sm">
          <div><p className="text-slate-400">Prompt</p><p className="text-slate-100">{threat.prompt || "-"}</p></div>
          <div><p className="text-slate-400">Risk Breakdown</p><p className="text-slate-100">{threat.risk_type} / {threat.severity} / score {threat.risk_score}</p></div>
          <div><p className="text-slate-400">Explanation</p><p className="text-slate-100">{threat.explanation || "Suspicious threat pattern detected."}</p></div>
          <div><p className="text-slate-400">Remediation</p><p className="text-cyan-300">{threat.remediation || "Investigate and reinforce controls."}</p></div>
        </div>
      </div>
    </div>
  );
}
