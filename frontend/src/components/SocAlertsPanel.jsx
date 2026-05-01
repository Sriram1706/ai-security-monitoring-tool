const sevStyle = {
  HIGH: "text-rose-300 bg-rose-500/15 border-rose-500/40",
  MEDIUM: "text-amber-300 bg-amber-500/15 border-amber-500/40",
  LOW: "text-emerald-300 bg-emerald-500/15 border-emerald-500/40",
};

export default function SocAlertsPanel({ alerts = [], onSelectAlert = () => {}, fullScreen = false }) {
  const listClass = fullScreen
    ? "space-y-2 h-[calc(100vh-300px)] min-h-[520px] overflow-auto pr-1"
    : "space-y-2 max-h-48 overflow-auto";

  return (
    <section className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold text-slate-100 mb-3">Alerts</h2>
      <div className={listClass}>
        {alerts.length === 0 && <p className="text-sm text-slate-400">No active alerts.</p>}
        {alerts.map((a, idx) => (
          <button
            key={`${a.type}-${a.timestamp}-${idx}`}
            type="button"
            onClick={() => onSelectAlert(a)}
            className="w-full text-left border border-slate-800 bg-slate-900 rounded-lg p-3 cursor-pointer hover:border-cyan-500/60 hover:bg-slate-800/80 transition-all interactive-card"
            title="Click to investigate"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm font-semibold text-slate-100">{a.type}</p>
              <span className={`text-xs border rounded px-2 py-1 ${sevStyle[a.severity] || sevStyle.MEDIUM}`}>{a.severity}</span>
            </div>
            <p className="text-xs text-slate-300 mt-1">{a.message}</p>
            <p className="text-xs text-slate-500 mt-1">{new Date(a.timestamp).toLocaleString()}</p>
          </button>
        ))}
      </div>
    </section>
  );
}
