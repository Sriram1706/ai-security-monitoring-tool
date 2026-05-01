import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { calculateSecurityScore } from "./SecurityScorePanel";
import {
  buildTimeBuckets,
  filterByTimeRange,
  getBucketSpec,
  latestTimestampMs,
  toLogTimestampMs,
} from "../lib/timeRange";

function isBlocked(row) {
  const status = String(row?.metadata?.status || row?.extra_metadata?.status || row?.status || "").toUpperCase();
  return Boolean(
    row?.blocked === true
    || row?.metadata?.blocked === true
    || row?.extra_metadata?.blocked === true
    || status === "BLOCKED",
  );
}

function buildTrendData(logs = [], timeRange = "24h") {
  const anchorMs = latestTimestampMs(logs);
  const scopedLogs = filterByTimeRange(logs, timeRange, anchorMs);
  const { bucketMs } = getBucketSpec(timeRange);
  const buckets = buildTimeBuckets(timeRange, anchorMs).map((b) => ({
    ...b,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    blocked: 0,
  }));

  const startMs = buckets[0]?.startMs || anchorMs;
  (scopedLogs || []).forEach((row) => {
    const ts = toLogTimestampMs(row);
    const idx = Math.floor((ts - startMs) / bucketMs);
    if (idx < 0 || idx >= buckets.length) return;
    const bucket = buckets[idx];
    const sev = String(row?.severity || "LOW").toUpperCase();
    bucket[sev] = (bucket[sev] || 0) + 1;
    if (isBlocked(row)) {
      bucket.blocked += 1;
    }
  });

  return buckets.map((bucket) => {
      const score = calculateSecurityScore({
        critical: bucket.CRITICAL || 0,
        high: bucket.HIGH || 0,
        medium: bucket.MEDIUM || 0,
        low: bucket.LOW || 0,
        blocked: bucket.blocked || 0,
        trend: "stable",
      }).score;
      return { time: bucket.label, score };
    });
}

export default function SecurityScoreTrendline({ logs = [], timeRange = "24h" }) {
  const data = buildTrendData(logs, timeRange);
  return (
    <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 h-80">
      <h3 className="text-lg font-semibold text-slate-100 mb-3">Security Score Trendline ({timeRange})</h3>
      <ResponsiveContainer width="100%" height="88%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="time" stroke="#94a3b8" />
          <YAxis domain={[0, 100]} stroke="#94a3b8" />
          <Tooltip />
          <Line
            type="monotone"
            dataKey="score"
            stroke="#22d3ee"
            strokeWidth={2.5}
            dot={{ r: 3 }}
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </section>
  );
}
