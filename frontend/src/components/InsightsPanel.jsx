export default function InsightsPanel({ logs = [], alerts = [] }) {
  const blocked = logs.filter((l) => l.metadata?.blocked).length;
  const attackCounts = logs.reduce((acc, l) => {
    const rt = l.findings?.[0]?.risk_type || "none";
    acc[rt] = (acc[rt] || 0) + 1;
    return acc;
  }, {});
  const entries = Object.entries(attackCounts).sort((a, b) => b[1] - a[1]);
  const mostFrequent = entries[0]?.[0] || "none";
  const highestRisk = logs.reduce((m, l) => (l.risk_score > (m?.risk_score || -1) ? l : m), null)?.findings?.[0]?.risk_type || "none";
  const half = Math.max(1, Math.floor(logs.length / 2));
  const oldAvg = logs.slice(half).reduce((s, l) => s + l.risk_score, 0) / Math.max(1, logs.slice(half).length);
  const newAvg = logs.slice(0, half).reduce((s, l) => s + l.risk_score, 0) / Math.max(1, logs.slice(0, half).length);
  const trend = newAvg > oldAvg + 5 ? "upward" : newAvg + 5 < oldAvg ? "downward" : "stable";

  return (
    <section className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold text-slate-100 mb-3">Insights Panel</h2>
      <ul className="space-y-2 text-sm text-slate-300">
        <li>Most frequent attack: <span className="text-amber-300 font-semibold">{mostFrequent}</span></li>
        <li>Highest risk detected: <span className="text-rose-300 font-semibold">{highestRisk}</span></li>
        <li>System risk trending: <span className="text-cyan-300 font-semibold">{trend}</span></li>
        <li>Blocked requests in feed: <span className="text-rose-300 font-semibold">{blocked}</span></li>
        <li>Active SOC alerts: <span className="text-cyan-300 font-semibold">{alerts.length}</span></li>
      </ul>
    </section>
  );
}
