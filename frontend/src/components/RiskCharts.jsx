import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import {
  buildTimeBuckets,
  filterByTimeRange,
  getBucketSpec,
  latestTimestampMs,
  toLogTimestampMs,
} from "../lib/timeRange";

const COLORS = ["#22d3ee", "#f59e0b", "#ef4444", "#22c55e"];

const bucketLabel = (score) => {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  return "Low";
};

export default function RiskCharts({ logs = [], timeRange = "24h" }) {
  const anchorMs = latestTimestampMs(logs);
  const scopedLogs = filterByTimeRange(logs, timeRange, anchorMs);
  const { bucketMs } = getBucketSpec(timeRange);
  const timeBuckets = buildTimeBuckets(timeRange, anchorMs).map((bucket) => ({ ...bucket, attacks: 0 }));
  const startMs = timeBuckets[0]?.startMs || anchorMs;

  (scopedLogs || []).forEach((row) => {
    const ts = toLogTimestampMs(row);
    const idx = Math.floor((ts - startMs) / bucketMs);
    if (idx < 0 || idx >= timeBuckets.length) return;
    timeBuckets[idx].attacks += 1;
  });
  const trendData = timeBuckets.map((bucket) => ({ time: bucket.label, attacks: bucket.attacks }));

  const riskBuckets = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  scopedLogs.forEach((row) => {
    riskBuckets[bucketLabel(row.risk_score)] += 1;
  });
  const riskDistribution = Object.entries(riskBuckets).map(([name, value]) => ({ name, value }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 h-80">
        <h3 className="font-semibold mb-2 text-slate-100">Attack Trends Over Time ({timeRange})</h3>
        <ResponsiveContainer width="100%" height="90%">
          <LineChart data={trendData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip />
            <Line type="monotone" dataKey="attacks" stroke="#22d3ee" strokeWidth={2.5} dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 h-80">
        <h3 className="font-semibold mb-2 text-slate-100">Risk Distribution</h3>
        <ResponsiveContainer width="100%" height="90%">
          <PieChart>
            <Pie data={riskDistribution} dataKey="value" nameKey="name" outerRadius={100}>
              {riskDistribution.map((entry, index) => (
                <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
