const statusStyle = {
  green: "bg-emerald-500",
  yellow: "bg-amber-400",
  red: "bg-rose-500",
};

function StatCard({ label, value, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Click to explore"
      className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 text-left transition hover:border-cyan-500/60 hover:bg-slate-900 cursor-pointer interactive-card"
    >
      <p className="text-xs uppercase tracking-wider text-slate-400">{label}</p>
      <p className="text-2xl font-bold text-slate-100 mt-1">{value}</p>
    </button>
  );
}

export default function ThreatIntelPanel({
  totalAttacks, criticalAlerts, injectionAttempts, dataLeakAttempts, status, onCardClick,
}) {
  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-100">Threat Intelligence Panel</h2>
        <div className="flex items-center gap-2 bg-slate-950/80 border border-slate-800 rounded-full px-3 py-1.5">
          <span className={`w-2.5 h-2.5 rounded-full ${statusStyle[status] || statusStyle.yellow}`} />
          <span className="text-xs text-slate-300 uppercase tracking-wider">System {status || "yellow"}</span>
        </div>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Total Attacks" value={totalAttacks} onClick={() => onCardClick?.("total")} />
        <StatCard label="Blocked Requests" value={criticalAlerts} onClick={() => onCardClick?.("blocked")} />
        <StatCard label="Prompt Injection Attempts" value={injectionAttempts} onClick={() => onCardClick?.("prompt_injection")} />
        <StatCard label="Data Leak Attempts" value={dataLeakAttempts} onClick={() => onCardClick?.("data_leak")} />
      </div>
    </section>
  );
}
