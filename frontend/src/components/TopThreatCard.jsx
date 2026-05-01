export default function TopThreatCard({ threat, onOpen }) {
  if (!threat) return null;

  return (
    <section className="rounded-xl border border-rose-500/40 bg-slate-950/90 p-4 shadow-[0_0_30px_rgba(244,63,94,0.18)]">
      <h2 className="text-lg font-semibold text-slate-100 mb-2">Top Threat</h2>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
        <div><p className="text-slate-400">Attack Type</p><p className="text-rose-300 font-semibold">{threat.risk_type}</p></div>
        <div><p className="text-slate-400">Count</p><p className="text-slate-100 font-semibold">{threat.count}</p></div>
        <div><p className="text-slate-400">Severity</p><p className="text-orange-300 font-semibold">{threat.severity}</p></div>
        <div><p className="text-slate-400">Impact</p><p className="text-slate-100">{threat.impact}</p></div>
        <div><p className="text-slate-400">Action</p><p className="text-cyan-300">{threat.action}</p></div>
      </div>
      <button onClick={onOpen} className="mt-3 bg-cyan-600 hover:bg-cyan-500 rounded px-3 py-2 text-sm font-semibold">
        Focus Mode
      </button>
    </section>
  );
}
