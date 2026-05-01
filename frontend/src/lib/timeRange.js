export const TIME_RANGE_OPTIONS = [
  { value: "1h", label: "Last 1h" },
  { value: "6h", label: "Last 6h" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7d" },
  { value: "30d", label: "Last 30d" },
];

export function timeRangeToMs(timeRange = "24h") {
  if (timeRange === "1h") return 60 * 60 * 1000;
  if (timeRange === "6h") return 6 * 60 * 60 * 1000;
  if (timeRange === "24h") return 24 * 60 * 60 * 1000;
  if (timeRange === "7d") return 7 * 24 * 60 * 60 * 1000;
  if (timeRange === "30d") return 30 * 24 * 60 * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}

export function toLogTimestampMs(row) {
  const dt = new Date(row?.created_at || row?.timestamp || 0);
  const ms = dt.getTime();
  return Number.isFinite(ms) ? ms : 0;
}

export function latestTimestampMs(rows = []) {
  const max = (rows || []).reduce((acc, row) => {
    const ms = toLogTimestampMs(row);
    return ms > acc ? ms : acc;
  }, 0);
  // Keep charts aligned to current time so stale data windows are visible as stale, not frozen.
  return Math.max(max, Date.now());
}

export function filterByTimeRange(rows = [], timeRange = "24h", anchorMs = latestTimestampMs(rows)) {
  const floor = anchorMs - timeRangeToMs(timeRange);
  return (rows || []).filter((row) => {
    const ts = toLogTimestampMs(row);
    return ts >= floor && ts <= anchorMs;
  });
}

export function getBucketSpec(timeRange = "24h") {
  if (timeRange === "1h") return { bucketMs: 5 * 60 * 1000, points: 12 };
  if (timeRange === "6h") return { bucketMs: 15 * 60 * 1000, points: 24 };
  if (timeRange === "24h") return { bucketMs: 60 * 60 * 1000, points: 24 };
  if (timeRange === "7d") return { bucketMs: 6 * 60 * 60 * 1000, points: 28 };
  if (timeRange === "30d") return { bucketMs: 24 * 60 * 60 * 1000, points: 30 };
  return { bucketMs: 60 * 60 * 1000, points: 24 };
}

export function formatBucketLabel(ms, timeRange = "24h") {
  const dt = new Date(ms);
  if (timeRange === "1h" || timeRange === "6h") {
    return `${String(dt.getHours()).padStart(2, "0")}:${String(dt.getMinutes()).padStart(2, "0")}`;
  }
  if (timeRange === "24h") {
    return `${String(dt.getHours()).padStart(2, "0")}:00`;
  }
  return `${String(dt.getDate()).padStart(2, "0")}/${String(dt.getMonth() + 1).padStart(2, "0")}`;
}

export function buildTimeBuckets(timeRange = "24h", anchorMs = Date.now()) {
  const { bucketMs, points } = getBucketSpec(timeRange);
  const start = anchorMs - (points - 1) * bucketMs;
  return Array.from({ length: points }, (_, idx) => {
    const ms = start + idx * bucketMs;
    return {
      startMs: ms,
      endMs: ms + bucketMs - 1,
      label: formatBucketLabel(ms, timeRange),
    };
  });
}
