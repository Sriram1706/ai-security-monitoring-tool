export default function HeroThreatPanel({
  threat,
  insightA,
  insightB,
  insightC,
  liveLabel,
}) {
  if (!threat) {
    return (
      <section className="glass-panel rounded-2xl border border-emerald-500/40 bg-slate-900/60 backdrop-blur p-6 text-center shadow-[0_0_30px_rgba(16,185,129,0.12)] fade-in">
        <h2 className="text-3xl font-bold text-emerald-300">System Stable</h2>
        <p className="text-slate-200 mt-2">No critical threats detected. Monitoring in real time.</p>
      </section>
    );
  }

  return (
    <section className="glass-panel rounded-2xl border border-rose-500/50 bg-slate-900/70 backdrop-blur p-6 md:p-8 text-center critical-glow fade-in">
      <div className="flex justify-center mb-2">
        <span className="inline-flex items-center gap-2 text-xs px-3 py-1 rounded-full border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 pulse-slow">
          <span className="w-2 h-2 rounded-full bg-cyan-400 blink-dot" />
          LIVE {liveLabel}
        </span>
      </div>
      <h2 className="text-3xl md:text-4xl font-extrabold text-rose-300">🚨 {threat.risk_type} Detected</h2>
      <p className="text-lg md:text-xl text-slate-100 mt-2">{threat.message}</p>
      <p className="text-sm text-cyan-300 mt-2">{threat.action}</p>
      <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
        <p className="text-slate-300 bg-slate-950/50 rounded-xl px-3 py-2">{insightA}</p>
        <p className="text-slate-300 bg-slate-950/50 rounded-xl px-3 py-2">{insightB}</p>
        <p className="text-slate-300 bg-slate-950/50 rounded-xl px-3 py-2">{insightC}</p>
      </div>
    </section>
  );
}
