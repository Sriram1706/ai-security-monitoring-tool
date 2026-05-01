import { getThreatExplanation } from "../lib/threatExplain";

const whyFlagged = (riskType) => {
  if (riskType === "prompt_injection") return "Contains override instruction pattern";
  if (riskType === "jailbreak_attempt") return "Detected jailbreak language and policy bypass cues";
  if (riskType === "data_exfiltration") return "Requests for secrets/system instructions";
  return "Risk indicators matched heuristic rules";
};

const riskExplanation = (riskType) => {
  if (riskType === "prompt_injection") return "User attempting to bypass model safeguards";
  if (riskType === "jailbreak_attempt") return "Potential attempt to disable guardrails";
  if (riskType === "data_exfiltration") return "Potential sensitive data exposure pathway";
  return "Potential unsafe model interaction";
};

const recommendedAction = (count) => (count >= 5 ? "Block" : count >= 2 ? "Investigate" : "Monitor");

export default function ThreatAnalysisPanel({ logs = [], onSelectThreat }) {
  const counts = logs.reduce((acc, row) => {
    (row.findings || []).forEach((f) => {
      const key = f.risk_type || "unknown";
      acc[key] = (acc[key] || 0) + 1;
    });
    return acc;
  }, {});

  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <section className="glass-panel bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold text-slate-100 mb-3">Threat Analysis Panel</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {top.length === 0 && <p className="text-sm text-slate-400">No threats detected yet.</p>}
        {top.map(([riskType, count]) => (
          <button
            key={riskType}
            type="button"
            onClick={() => onSelectThreat?.(riskType)}
            className={`rounded-lg border bg-slate-900 p-3 text-left transition hover:border-cyan-500/60 ${
              count >= 5 ? "active-threat critical-glow" : "border-slate-800 low-noise"
            }`}
          >
            {(() => {
              const ai = getThreatExplanation(riskType);
              return (
                <>
            <p className="text-xs text-slate-400 uppercase tracking-wide">{riskType}</p>
            <p className="text-xl font-bold text-slate-100 mt-1">{count}</p>
            <p className="text-xs text-slate-300 mt-2">Why flagged: {whyFlagged(riskType)}</p>
            <p className="text-xs text-slate-300 mt-1">Risk explanation: {riskExplanation(riskType)}</p>
            <p className="text-xs text-slate-300 mt-2"><span className="text-slate-400">What happened:</span> {ai.what_happened}</p>
            <p className="text-xs text-slate-300 mt-1"><span className="text-slate-400">Why risky:</span> {ai.why_risky}</p>
            <p className="text-xs text-slate-300 mt-1"><span className="text-slate-400">Impact:</span> {ai.impact}</p>
            <p className="text-xs text-slate-400 mt-1">Confidence: {Math.min(95, 55 + count * 7)}%</p>
            <div className="mt-2 rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-1 text-xs text-cyan-300">
              Recommended action: {ai.recommended_action || recommendedAction(count)}
            </div>
                </>
              );
            })()}
          </button>
        ))}
      </div>
    </section>
  );
}
