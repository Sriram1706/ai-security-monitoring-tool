const clamp = (n, min, max) => Math.max(min, Math.min(max, n));

function InfoHint({ text }) {
  return (
    <span
      title={text}
      aria-label="How calculated"
      className="ml-1 inline-flex h-4 w-4 items-center justify-center rounded-full border border-slate-600 text-[10px] text-slate-300 cursor-help"
    >
      i
    </span>
  );
}

const statusFor = (score) => {
  if (score >= 80) return "Good";
  if (score >= 60) return "Moderate";
  if (score >= 30) return "Risky";
  return "Critical";
};

const colorFor = (score) => {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#06b6d4";
  if (score >= 30) return "#f59e0b";
  return "#f43f5e";
};

export function calculateSecurityScore({ critical, high, medium, low, blocked, trend }) {
  const total = critical + high + medium + low;
  let score = 100;
  if (total > 0) {
    const riskRatio = (
      critical * 1.0 +
      high * 0.7 +
      medium * 0.4 +
      low * 0.1
    ) / total;
    score = Math.floor((1 - riskRatio) * 100);
  }
  score = clamp(score + blocked * 2, 0, 100);
  if (score < 10) score = 10;
  return {
    score,
    status: statusFor(score),
    trend: trend || "stable",
    critical,
    high,
    medium,
    blocked,
  };
}

export default function SecurityScorePanel({
  logs = [],
  trend = "stable",
  onMetricClick = () => {},
}) {
  const severityCounts = logs.reduce(
    (acc, l) => {
      const sev = (l.severity || "LOW").toUpperCase();
      acc[sev] = (acc[sev] || 0) + 1;
      if (l.metadata?.blocked) acc.blocked += 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, blocked: 0 },
  );

  const scoreData = calculateSecurityScore({
    critical: severityCounts.CRITICAL,
    high: severityCounts.HIGH,
    medium: severityCounts.MEDIUM,
    low: severityCounts.LOW,
    blocked: severityCounts.blocked,
    trend,
  });
  const score = scoreData.score;
  const color = colorFor(score);
  const label = scoreData.status;
  const ring = `conic-gradient(${color} ${score * 3.6}deg, rgba(30,41,59,0.9) 0deg)`;

  return (
    <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 shadow-[0_0_30px_rgba(56,189,248,0.12)] fade-in">
      <h2 className="text-lg font-semibold text-slate-100">
        Security Score
        <InfoHint text="Score formula: floor((1 - ((critical*1.0 + high*0.7 + medium*0.4 + low*0.1) / total)) * 100), then +2 per blocked, clamped 0-100 with minimum 10." />
      </h2>
      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
        <button
          type="button"
          onClick={() => onMetricClick("score")}
          className="mx-auto h-40 w-40 rounded-full p-2 transition-all duration-200 hover:scale-105 hover:shadow-[0_0_28px_rgba(56,189,248,0.28)] interactive-card"
          style={{ background: ring }}
          title="Click to inspect security score findings"
        >
          <div className="h-full w-full rounded-full bg-slate-950/90 border border-slate-800 flex flex-col items-center justify-center">
            <p className="text-4xl font-bold" style={{ color }}>{score}</p>
            <p className="text-sm text-slate-400">{label}</p>
          </div>
        </button>
        <div className="grid grid-cols-1 gap-3 text-sm">
          <button
            type="button"
            onClick={() => onMetricClick("posture")}
            title="Click to inspect posture findings"
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-left text-slate-300 transition-all hover:border-cyan-500/50 hover:bg-slate-800/90 interactive-card"
          >
            Current Posture: <span className="text-slate-100 font-semibold">{label}</span>
            <InfoHint text="Posture bands: 80+ Good, 60-79 Moderate, 30-59 Risky, below 30 Critical." />
          </button>
          <button
            type="button"
            onClick={() => onMetricClick("trend")}
            title="Click to open trend analysis"
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-left text-slate-300 transition-all hover:border-cyan-500/50 hover:bg-slate-800/90 interactive-card"
          >
            Trend Signal: <span className="text-cyan-300 font-semibold">{scoreData.trend}</span>
            <InfoHint text="Trend compares recent windows: upward means rising risk; stable/downward means flat or improving." />
          </button>
          <button
            type="button"
            onClick={() => onMetricClick("processed")}
            title="Click to open processed findings"
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-left text-slate-300 transition-all hover:border-cyan-500/50 hover:bg-slate-800/90 interactive-card"
          >
            Findings Processed: <span className="text-slate-100 font-semibold">{logs.length}</span>
            <InfoHint text="Count of findings in current filtered scope and selected chart window where applicable." />
          </button>
        </div>
      </div>
      <p className="mt-3 text-sm text-slate-400">Trend over time: <span className="text-cyan-300 font-medium">{scoreData.trend}</span></p>
    </section>
  );
}
