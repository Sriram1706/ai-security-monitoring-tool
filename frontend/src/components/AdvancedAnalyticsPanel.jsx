import {
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  buildTimeBuckets,
  filterByTimeRange,
  getBucketSpec,
  latestTimestampMs,
  timeRangeToMs,
  toLogTimestampMs,
} from "../lib/timeRange";

const chartTheme = {
  grid: "#1f2937",
  axis: "#94a3b8",
  tooltipBg: "#0f172a",
  tooltipBorder: "#334155",
};

const RISK_COLORS = {
  LOW: "#22C55E",
  MEDIUM: "#EAB308",
  HIGH: "#F97316",
  CRITICAL: "#EF4444",
};

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

function getRiskType(row) {
  return row?.risk_type || row?.findings?.[0]?.risk_type || "none";
}

function getSeverity(row) {
  return String(row?.severity || "LOW").toUpperCase();
}

function isBlocked(row) {
  const status = String(row?.metadata?.status || row?.extra_metadata?.status || "").toUpperCase();
  return (
    row?.blocked === true ||
    row?.metadata?.blocked === true ||
    row?.extra_metadata?.blocked === true ||
    status === "BLOCKED"
  );
}

function isInjection(row) {
  const type = getRiskType(row);
  return ["prompt_injection", "indirect_prompt_injection", "jailbreak_attempt"].includes(type);
}

function isJailbreak(row) {
  return getRiskType(row) === "jailbreak_attempt";
}

function isExfiltration(row) {
  const type = getRiskType(row);
  return ["data_exfiltration", "sensitive_data_exposure"].includes(type);
}

function countInWindow(logs, windowMs, predicate = () => true, anchorMs = Date.now()) {
  const floor = anchorMs - windowMs;
  return (logs || []).filter((row) => {
    const ts = toLogTimestampMs(row);
    return ts >= floor && ts <= anchorMs && predicate(row);
  }).length;
}

function buildSeries(logs, predicate, timeRange = "24h", anchorMs = Date.now()) {
  const buckets = buildTimeBuckets(timeRange, anchorMs);
  const { bucketMs } = getBucketSpec(timeRange);
  const startMs = buckets[0]?.startMs || anchorMs;
  const rows = buckets.map((bucket) => ({
    time: bucket.label,
    value: 0,
  }));

  (logs || []).forEach((row) => {
    if (!predicate(row)) return;
    const ts = toLogTimestampMs(row);
    const idx = Math.floor((ts - startMs) / bucketMs);
    if (idx < 0 || idx >= rows.length) return;
    rows[idx].value += 1;
  });

  return rows;
}

function buildRiskScoreSeries(logs, timeRange = "24h", anchorMs = Date.now()) {
  const buckets = buildTimeBuckets(timeRange, anchorMs);
  const { bucketMs } = getBucketSpec(timeRange);
  const startMs = buckets[0]?.startMs || anchorMs;
  const rows = buckets.map((bucket) => ({
    time: bucket.label,
    score: 0,
    n: 0,
  }));

  (logs || []).forEach((row) => {
    const ts = toLogTimestampMs(row);
    const idx = Math.floor((ts - startMs) / bucketMs);
    if (idx < 0 || idx >= rows.length) return;
    rows[idx].score += Number(row?.risk_score) || 0;
    rows[idx].n += 1;
  });

  return rows.map((r) => ({
    time: r.time,
    score: r.n > 0 ? Number((r.score / r.n).toFixed(2)) : 0,
  }));
}

function ChartCard({ title, children, className = "" }) {
  return (
    <section className={`rounded-xl border border-slate-800 bg-slate-950/60 p-3 ${className}`}>
      <h3 className="text-sm font-semibold text-slate-200 mb-2">{title}</h3>
      {children}
    </section>
  );
}

function TinyStat({ label, value, tone = "text-slate-100", suffix = "", onClick, title = "", hint = "" }) {
  const Wrapper = onClick ? "button" : "article";
  return (
    <Wrapper
      type={onClick ? "button" : undefined}
      onClick={onClick}
      title={title || undefined}
      className={`rounded-xl border border-slate-800 bg-slate-950/60 p-3 hover:border-cyan-500/50 transition-all ${onClick ? "interactive-card text-left" : ""}`}
    >
      <p className="text-xs text-slate-400">
        {label}
        {hint ? <InfoHint text={hint} /> : null}
      </p>
      <p className={`mt-1 text-4xl font-bold ${tone}`}>{value}{suffix}</p>
    </Wrapper>
  );
}

export default function AdvancedAnalyticsPanel({ logs = [], alerts = [], metrics = {}, timeRange = "24h", onOpenDrilldown = () => {} }) {
  const safeLogs = Array.isArray(logs) ? logs : [];
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const timeAnchorMs = latestTimestampMs(safeLogs);
  const windowMs = timeRangeToMs(timeRange);
  const scopedLogs = filterByTimeRange(safeLogs, timeRange, timeAnchorMs);
  const windowLabel = String(timeRange).toUpperCase();

  const totalRequestsInRange = countInWindow(safeLogs, windowMs, () => true, timeAnchorMs);
  const blockedInRange = countInWindow(safeLogs, windowMs, isBlocked, timeAnchorMs);
  const blockRate = totalRequestsInRange > 0 ? (blockedInRange / totalRequestsInRange) * 100 : 0;
  const injectionInRange = countInWindow(safeLogs, windowMs, isInjection, timeAnchorMs);
  const injectionRatePerMin = windowMs > 0 ? injectionInRange / (windowMs / (60 * 1000)) : 0;
  const currentRiskScore = Math.round(
    Number(metrics?.avg_risk_score) ||
      (scopedLogs.length > 0
        ? scopedLogs.slice(0, 20).reduce((s, r) => s + (Number(r?.risk_score) || 0), 0) / Math.min(20, scopedLogs.length)
        : 0),
  );
  const systemStatus = currentRiskScore > 70 ? "RED" : currentRiskScore >= 40 ? "YELLOW" : "GREEN";
  const systemTone = systemStatus === "RED" ? "bg-red-600/90 text-white" : systemStatus === "YELLOW" ? "bg-amber-500/90 text-slate-950" : "bg-emerald-600/80 text-white";

  const criticalAlerts = countInWindow(safeLogs, windowMs, (r) => getSeverity(r) === "CRITICAL", timeAnchorMs);
  const highAlerts = countInWindow(safeLogs, windowMs, (r) => getSeverity(r) === "HIGH", timeAnchorMs);

  const alertTypes = Object.entries(
    (scopedLogs || []).reduce((acc, row) => {
      const sev = getSeverity(row);
      if (!["HIGH", "CRITICAL"].includes(sev)) return acc;
      const key = getRiskType(row);
      acc[key] = acc[key] || { count: 0, last: 0 };
      acc[key].count += 1;
      acc[key].last = Math.max(acc[key].last, toLogTimestampMs(row));
      return acc;
    }, {}),
  )
    .map(([type, v]) => ({ type, count: v.count, last: v.last }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const injectionSeries = buildSeries(scopedLogs, isInjection, timeRange, timeAnchorMs);
  const blockedSeries = buildSeries(scopedLogs, isBlocked, timeRange, timeAnchorMs);
  const jailbreakSeries = buildSeries(scopedLogs, isJailbreak, timeRange, timeAnchorMs);
  const exfilSeries = buildSeries(scopedLogs, isExfiltration, timeRange, timeAnchorMs);
  const scoreSeries = buildRiskScoreSeries(scopedLogs, timeRange, timeAnchorMs);

  const riskDistribution = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((key) => ({
    name: key,
    value: scopedLogs.filter((r) => getSeverity(r) === key).length,
  }));

  const baseline = Number(
    (
      injectionSeries.slice(0, Math.max(1, injectionSeries.length - 1)).reduce((sum, row) => sum + row.value, 0) /
      Math.max(1, injectionSeries.length - 1)
    ).toFixed(4),
  );
  const current = Number((injectionSeries[injectionSeries.length - 1]?.value || 0).toFixed(4));
  const anomalyDetected = current > 0 && current >= baseline * 2;
  const anomalyScore = Number((baseline > 0 ? current / baseline : current).toFixed(4));

  const anomalySeries = injectionSeries.map((p) => ({
    time: p.time,
    current: p.value,
    baseline,
  }));

  const heatWindow = injectionSeries.slice(-18).map((_, idx) => idx);
  const heatRows = [
    { label: "Injection", series: injectionSeries.slice(-18).map((p) => p.value) },
    { label: "Jailbreak", series: jailbreakSeries.slice(-18).map((p) => p.value) },
    { label: "Exfiltration", series: exfilSeries.slice(-18).map((p) => p.value) },
  ];
  const heatMax = Math.max(1, ...heatRows.flatMap((r) => r.series));

  const drillRows = scopedLogs
    .slice(0, 10)
    .map((r) => ({
      prompt: r?.prompt || "",
      risk_type: getRiskType(r),
      severity: getSeverity(r),
      timestamp: r?.created_at || r?.timestamp,
      remediation: (r?.findings?.[0]?.remediation || []).join(" | "),
    }));

  return (
    <div className="space-y-4">
      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-xl font-semibold text-slate-100 mb-3">Threat Intelligence</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
          <TinyStat
            label={`Total Requests (${windowLabel})`}
            value={totalRequestsInRange}
            tone="text-emerald-300"
            onClick={() => onOpenDrilldown("Advanced Analytics: Total Requests", drillRows)}
            title="Click to inspect request sample"
            hint="Count of logs in selected chart window."
          />
          <TinyStat
            label="Block Rate (%)"
            value={blockRate.toFixed(2)}
            suffix="%"
            tone="text-rose-300"
            onClick={() => onOpenDrilldown("Advanced Analytics: Blocked", drillRows.filter((r) => String(r?.severity || "").toUpperCase() !== "LOW"))}
            title="Click to inspect blocked/high-risk sample"
            hint="Formula: (blocked requests in window / total requests in window) * 100."
          />
          <TinyStat
            label={`Injection Rate (${windowLabel})`}
            value={injectionRatePerMin.toFixed(2)}
            suffix=" /min"
            tone="text-emerald-300"
            onClick={() => onOpenDrilldown("Advanced Analytics: Injection", drillRows.filter((r) => String(r?.risk_type || "").includes("injection")))}
            title="Click to inspect injection sample"
            hint="Injection detections normalized per minute within selected window."
          />
          <TinyStat
            label="Current Risk Score"
            value={currentRiskScore}
            tone="text-rose-300"
            onClick={() => onOpenDrilldown("Advanced Analytics: Risk Score", drillRows)}
            title="Click to inspect risk-score sample"
            hint="Uses backend avg_risk_score when available; otherwise recent sample average."
          />
          <article className={`rounded-xl border border-slate-800 p-3 ${systemTone}`}>
            <p className="text-xs opacity-80">System Status</p>
            <p className="mt-1 text-5xl font-bold tracking-wide">{systemStatus}</p>
          </article>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-xl font-semibold text-slate-100 mb-3">SOC Alerts</h2>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
          <TinyStat label="CRITICAL Alerts" value={criticalAlerts} tone="text-rose-300" />
          <TinyStat label="HIGH Alerts" value={highAlerts} tone="text-orange-300" />
          <ChartCard title="Alert Type / Count / Last Triggered">
            <div className="space-y-2 max-h-[220px] overflow-auto">
              {alertTypes.length === 0 && <p className="text-sm text-slate-400">No high-severity alert activity.</p>}
              {alertTypes.map((row) => (
                <button
                  key={`alert-type-${row.type}`}
                  type="button"
                  onClick={() => onOpenDrilldown("Alert Type Drill-down", drillRows.filter((d) => d.risk_type === row.type))}
                  title="Click to open related logs"
                  className="w-full text-left rounded-lg border border-slate-800 bg-slate-900/50 p-2 hover:border-cyan-500/50"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-cyan-300">{row.type}</span>
                    <span className="text-sm text-slate-200">{row.count}</span>
                  </div>
                  <p className="text-xs text-slate-400">{row.last ? new Date(row.last).toLocaleString() : "-"}</p>
                </button>
              ))}
              {safeAlerts.length > 0 && (
                <p className="text-xs text-slate-500">Active alert events in queue: {safeAlerts.length}</p>
              )}
            </div>
          </ChartCard>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-xl font-semibold text-slate-100 mb-3">Attack Monitoring</h2>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <ChartCard title="Live Injection Rate">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={injectionSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="time" stroke={chartTheme.axis} minTickGap={24} />
                  <YAxis stroke={chartTheme.axis} />
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Line type="monotone" dataKey="value" stroke="#22C55E" strokeWidth={2.2} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
          <ChartCard title="Blocked Requests Trend">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={blockedSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="time" stroke={chartTheme.axis} minTickGap={24} />
                  <YAxis stroke={chartTheme.axis} />
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Line type="monotone" dataKey="value" stroke="#F43F5E" strokeWidth={2.2} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
          <ChartCard title="Jailbreak Attempts">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={jailbreakSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="time" stroke={chartTheme.axis} minTickGap={24} />
                  <YAxis stroke={chartTheme.axis} />
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Line type="monotone" dataKey="value" stroke="#84CC16" strokeWidth={2.2} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
          <ChartCard title="Data Exfiltration Attempts">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={exfilSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="time" stroke={chartTheme.axis} minTickGap={24} />
                  <YAxis stroke={chartTheme.axis} />
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Line type="monotone" dataKey="value" stroke="#F97316" strokeWidth={2.2} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-xl font-semibold text-slate-100 mb-3">Risk Analysis</h2>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <ChartCard title="Risk Score Trend">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={scoreSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="time" stroke={chartTheme.axis} minTickGap={24} />
                  <YAxis stroke={chartTheme.axis} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Line type="monotone" dataKey="score" stroke="#38BDF8" strokeWidth={2.4} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
          <ChartCard title="Risk Distribution (LOW/MEDIUM/HIGH/CRITICAL)">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskDistribution}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={64}
                    outerRadius={92}
                    paddingAngle={2}
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {riskDistribution.map((row) => (
                      <Cell key={`risk-dist-${row.name}`} fill={RISK_COLORS[row.name]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-xl font-semibold text-slate-100 mb-3">Anomaly Detection</h2>
        <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-3">
          <ChartCard title="Current vs Baseline Injection Rate">
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={anomalySeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="time" stroke={chartTheme.axis} minTickGap={24} />
                  <YAxis stroke={chartTheme.axis} />
                  <Tooltip contentStyle={{ background: chartTheme.tooltipBg, borderColor: chartTheme.tooltipBorder }} />
                  <Line type="monotone" dataKey="current" stroke="#22C55E" strokeWidth={2.2} dot={false} name="Current" />
                  <Line type="monotone" dataKey="baseline" stroke="#EAB308" strokeWidth={2} dot={false} name="Baseline" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
          <article
            className={`rounded-xl border p-3 ${anomalyDetected ? "border-rose-500/60 bg-rose-500/20" : "border-emerald-500/40 bg-emerald-500/15"}`}
            title="Anomaly status based on current vs baseline injection rate"
          >
            <p className="text-xs text-slate-100/90">ANOMALY STATUS</p>
            <p className={`mt-2 text-2xl font-bold ${anomalyDetected ? "text-rose-200" : "text-emerald-200"}`}>
              {anomalyDetected ? "ANOMALY DETECTED" : "NORMAL"}
            </p>
            <p className="mt-4 text-sm text-slate-100/90">Current: {current}</p>
            <p className="text-sm text-slate-100/90">Baseline: {baseline}</p>
            <p className="text-sm text-slate-100/90">Delta Ratio: {anomalyScore}</p>
          </article>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-xl font-semibold text-slate-100 mb-3">Advanced Visuals</h2>
        <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-3">
          <ChartCard title="Attack Heatmap (Injection/Jailbreak/Exfiltration)">
            <div className="space-y-2">
              {heatRows.map((row) => (
                <div key={`heat-row-${row.label}`} className="grid grid-cols-[140px_1fr] items-center gap-2">
                  <span className="text-xs text-slate-300">{row.label}</span>
                  <div className="grid gap-1" style={{ gridTemplateColumns: "repeat(18, minmax(0, 1fr))" }}>
                    {heatWindow.map((idx) => {
                      const value = row.series[idx] || 0;
                      const alpha = value > 0 ? Math.max(0.18, value / heatMax) : 0.08;
                      return (
                        <button
                          key={`heat-${row.label}-${idx}`}
                          type="button"
                          title={`${row.label} | ${injectionSeries.slice(-18)[idx]?.time || "-"} | count: ${value}`}
                          className="h-6 rounded border border-slate-800"
                          style={{ backgroundColor: `rgba(249,115,22,${alpha})` }}
                        />
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </ChartCard>
          <ChartCard title="Drill-down: Security Logs">
            <div className="space-y-2 max-h-[250px] overflow-auto pr-1">
              {drillRows.length === 0 && <p className="text-sm text-slate-400">No logs available.</p>}
              {drillRows.map((row, idx) => (
                <button
                  key={`drill-${idx}`}
                  type="button"
                  title="Click to open selected log details"
                  onClick={() => onOpenDrilldown("Security Log Drill-down", [row])}
                  className="w-full text-left rounded-lg border border-slate-800 bg-slate-900/50 p-2 hover:border-cyan-500/50"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-cyan-300">{row.timestamp ? new Date(row.timestamp).toLocaleString() : "-"}</span>
                    <span className="text-xs text-slate-300">{row.risk_type}</span>
                  </div>
                  <p className="mt-1 text-xs text-slate-200 truncate">{row.prompt || "-"}</p>
                </button>
              ))}
            </div>
          </ChartCard>
        </div>
      </section>
    </div>
  );
}
