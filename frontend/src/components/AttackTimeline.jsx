import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceDot,
} from "recharts";
import {
  buildTimeBuckets,
  filterByTimeRange,
  getBucketSpec,
  latestTimestampMs,
  toLogTimestampMs,
} from "../lib/timeRange";

const sevColor = {
  CRITICAL: "text-rose-300",
  HIGH: "text-orange-300",
  MEDIUM: "text-amber-300",
  LOW: "text-emerald-300",
};

export default function AttackTimeline({ entries = [], timeRange = "24h", onOpenDrilldown = () => {} }) {
  const anchorMs = latestTimestampMs(entries);
  const scopedEntries = filterByTimeRange(entries, timeRange, anchorMs);
  const { bucketMs } = getBucketSpec(timeRange);
  const buckets = buildTimeBuckets(timeRange, anchorMs).map((b) => ({ ...b, events: 0, critical: 0 }));
  const startMs = buckets[0]?.startMs || anchorMs;

  (scopedEntries || []).forEach((e) => {
    const ts = toLogTimestampMs({ created_at: e?.timestamp || e?.created_at });
    const idx = Math.floor((ts - startMs) / bucketMs);
    if (idx < 0 || idx >= buckets.length) return;
    buckets[idx].events += 1;
    if ((e?.severity || "").toUpperCase() === "CRITICAL") buckets[idx].critical += 1;
  });

  const chartData = buckets.map((b) => ({ time: b.label, events: b.events, critical: b.critical }));
  const avg = chartData.length > 0 ? chartData.reduce((s, r) => s + r.events, 0) / chartData.length : 0;
  const spikes = chartData.filter((r) => r.events >= Math.max(3, Math.ceil(avg * 1.8)));

  const criticalEvents = (scopedEntries || [])
    .filter((e) => (e?.severity || "").toUpperCase() === "CRITICAL")
    .slice(0, 8);

  return (
    <section className="bg-slate-950/80 border border-slate-800 rounded-2xl p-4 slide-in shadow-[0_0_25px_rgba(56,189,248,0.08)]">
      <h2 className="text-lg font-semibold text-slate-100 mb-1">Attack Timeline</h2>
      <p className="text-xs text-slate-400 mb-3">Window: {timeRange}. Red markers indicate spikes.</p>

      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #334155" }}
              formatter={(value, name) => [value, name === "events" ? "Events" : "Critical"]}
            />
            <Line type="monotone" dataKey="events" stroke="#22d3ee" strokeWidth={2.5} dot={{ r: 2 }} />
            <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 1 }} />
            {spikes.map((s) => (
              <ReferenceDot key={s.time} x={s.time} y={s.events} r={5} fill="#ef4444" stroke="#fecaca" />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-3">
        <h3 className="text-sm font-semibold text-slate-200 mb-2">Critical Events</h3>
        <div className="space-y-2 h-[calc(100vh-430px)] min-h-[280px] overflow-auto pr-1">
          {criticalEvents.length === 0 && <p className="text-xs text-slate-400">No critical events.</p>}
          {criticalEvents.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() =>
                onOpenDrilldown("Critical Event", [
                  {
                    prompt: item?.prompt || "",
                    risk_type: item?.risk_type || "unknown",
                    severity: item?.severity || "CRITICAL",
                    timestamp: item?.timestamp,
                    remediation: "Escalate and enforce stricter controls.",
                  },
                ])
              }
              className="w-full text-left rounded-lg border border-slate-800 bg-slate-900 p-3 cursor-pointer hover:border-rose-500/60"
            >
              <div className="flex flex-wrap gap-2 items-center justify-between">
                <p className="text-sm font-semibold text-cyan-300">{item.risk_type}</p>
                <span className={`text-xs ${sevColor[item.severity] || "text-slate-300"}`}>{item.severity}</span>
              </div>
              <p className="text-xs text-slate-300 mt-1">{(item.prompt || "").slice(0, 120)}{(item.prompt || "").length > 120 ? "..." : ""}</p>
              <p className="text-xs text-slate-500 mt-1">{new Date(item.timestamp).toLocaleString()}</p>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
