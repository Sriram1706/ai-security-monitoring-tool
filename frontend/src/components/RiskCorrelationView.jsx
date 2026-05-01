import { useEffect, useMemo, useState } from "react";

function riskTypeOf(item) {
  return item?.risk_type || item?.findings?.[0]?.risk_type || "none";
}

function prettyRiskName(value = "unknown") {
  const raw = String(value || "unknown");
  if (raw === "none") return "No Risk Detected";
  return raw
    .replaceAll("_", " ")
    .split(" ")
    .map((w) => (w ? `${w[0].toUpperCase()}${w.slice(1)}` : w))
    .join(" ");
}

function shortRiskName(value = "unknown", max = 18) {
  const pretty = prettyRiskName(value);
  if (pretty.length <= max) return pretty;
  return `${pretty.slice(0, max - 1)}…`;
}

function isBlockedLog(log) {
  if (!log) return false;
  const status = String(log?.status || log?.metadata?.status || log?.extra_metadata?.status || "").toUpperCase();
  const blockedField =
    log?.blocked ??
    log?.metadata?.blocked ??
    log?.extra_metadata?.blocked ??
    false;
  return status === "BLOCKED" || blockedField === true || blockedField === 1 || blockedField === "1";
}

function toMillis(ts) {
  if (!ts) return 0;
  const t = new Date(ts).getTime();
  return Number.isFinite(t) ? t : 0;
}

function severityRank(severity = "LOW") {
  const sev = String(severity || "LOW").toUpperCase();
  if (sev === "CRITICAL") return 4;
  if (sev === "HIGH") return 3;
  if (sev === "MEDIUM") return 2;
  return 1;
}

function severityColor(severity = "LOW") {
  const sev = String(severity || "LOW").toUpperCase();
  if (sev === "CRITICAL") return "#EF4444";
  if (sev === "HIGH") return "#F97316";
  if (sev === "MEDIUM") return "#EAB308";
  return "#22C55E";
}

function parseWindowMs(windowKey) {
  if (windowKey === "5m") return 5 * 60 * 1000;
  if (windowKey === "1h") return 60 * 60 * 1000;
  if (windowKey === "6h") return 6 * 60 * 60 * 1000;
  if (windowKey === "24h") return 24 * 60 * 60 * 1000;
  if (windowKey === "7d") return 7 * 24 * 60 * 60 * 1000;
  if (windowKey === "30d") return 30 * 24 * 60 * 60 * 1000;
  return 0;
}

export default function RiskCorrelationView({ logs = [], attackPathEdges = [], timeRange = "24h", onOpenDrilldown = () => {} }) {
  const [timeWindow, setTimeWindow] = useState(timeRange || "24h");
  const [selectedEdgeKey, setSelectedEdgeKey] = useState("");
  const [selectedNode, setSelectedNode] = useState("");

  useEffect(() => {
    if (!timeRange) return;
    setTimeWindow(timeRange);
  }, [timeRange]);

  const orderedAll = useMemo(
    () =>
      (logs || [])
        .filter((l) => toMillis(l?.created_at) > 0)
        .slice()
        .sort((a, b) => toMillis(a?.created_at) - toMillis(b?.created_at)),
    [logs],
  );

  const now = Date.now();
  const windowMs = parseWindowMs(timeWindow);
  const currentStart = windowMs > 0 ? now - windowMs : 0;
  const prevStart = windowMs > 0 ? now - (2 * windowMs) : 0;
  const prevEnd = windowMs > 0 ? now - windowMs : 0;

  const currentLogs = useMemo(
    () => orderedAll.filter((l) => (windowMs > 0 ? toMillis(l?.created_at) >= currentStart : true)),
    [orderedAll, windowMs, currentStart],
  );
  const previousLogs = useMemo(
    () =>
      windowMs > 0
        ? orderedAll.filter((l) => {
            const t = toMillis(l?.created_at);
            return t >= prevStart && t < prevEnd;
          })
        : [],
    [orderedAll, windowMs, prevStart, prevEnd],
  );

  const buildEdges = (items, includeExternalEdges = false) => {
    const map = new Map();
    for (let i = 0; i < items.length - 1; i += 1) {
      const fromLog = items[i];
      const toLog = items[i + 1];
      const from = riskTypeOf(fromLog);
      const to = riskTypeOf(toLog);
      if (!from || !to || from === "none" || to === "none") continue;
      const key = `${from}=>${to}`;
      const existing = map.get(key) || {
        from,
        to,
        count: 0,
        totalScore: 0,
        blockedCount: 0,
        maxSeverityRank: 1,
        lastSeen: 0,
      };
      existing.count += 1;
      existing.totalScore += Number(toLog?.risk_score || fromLog?.risk_score || 0);
      const blocked = isBlockedLog(toLog) || isBlockedLog(fromLog);
      existing.blockedCount += blocked ? 1 : 0;
      existing.maxSeverityRank = Math.max(
        existing.maxSeverityRank,
        severityRank(fromLog?.severity),
        severityRank(toLog?.severity),
      );
      existing.lastSeen = Math.max(existing.lastSeen, toMillis(toLog?.created_at), toMillis(fromLog?.created_at));
      map.set(key, existing);
    }

    if (includeExternalEdges) {
      (attackPathEdges || []).forEach((edge) => {
        const from = edge?.source_risk;
        const to = edge?.target_risk;
        if (!from || !to) return;
        const key = `${from}=>${to}`;
        const existing = map.get(key) || {
          from,
          to,
          count: 0,
          totalScore: 0,
          blockedCount: 0,
          maxSeverityRank: 2,
          lastSeen: 0,
        };
        existing.count += Number(edge?.count || 0);
        map.set(key, existing);
      });
    }
    return map;
  };

  const currentEdgeMap = useMemo(
    () => buildEdges(currentLogs, true),
    [currentLogs, attackPathEdges],
  );
  const previousEdgeMap = useMemo(
    () => buildEdges(previousLogs, false),
    [previousLogs],
  );

  const edges = useMemo(() => {
    const rows = Array.from(currentEdgeMap.values()).map((e) => {
      const prev = previousEdgeMap.get(`${e.from}=>${e.to}`);
      const previousCount = Number(prev?.count || 0);
      const delta = e.count - previousCount;
      const trend = delta > 0 ? "up" : delta < 0 ? "down" : "flat";
      const avgScore = e.count > 0 ? Math.round(e.totalScore / e.count) : 0;
      const blockedRate = e.count > 0 ? Math.round((e.blockedCount / e.count) * 100) : 0;
      const confidence = Math.min(100, Math.round((e.count / Math.max(1, currentLogs.length)) * 120));
      const severity =
        e.maxSeverityRank >= 4 ? "CRITICAL" : e.maxSeverityRank >= 3 ? "HIGH" : e.maxSeverityRank >= 2 ? "MEDIUM" : "LOW";
      return {
        ...e,
        key: `${e.from}=>${e.to}`,
        avgScore,
        blockedRate,
        confidence,
        previousCount,
        delta,
        trend,
        severity,
      };
    });
    return rows.sort((a, b) => b.count - a.count).slice(0, 16);
  }, [currentEdgeMap, previousEdgeMap, currentLogs.length]);

  const graphEdges = useMemo(() => edges.slice(0, 9), [edges]);

  const nodes = useMemo(() => {
    const map = new Map();
    graphEdges.forEach((edge) => {
      const add = (name, side) => {
        const existing = map.get(name) || {
          name,
          in: 0,
          out: 0,
          total: 0,
          maxSeverityRank: 1,
          blockedCount: 0,
        };
        existing.total += edge.count;
        existing.maxSeverityRank = Math.max(existing.maxSeverityRank, severityRank(edge.severity));
        existing.blockedCount += edge.blockedCount || 0;
        if (side === "in") existing.in += edge.count;
        if (side === "out") existing.out += edge.count;
        map.set(name, existing);
      };
      add(edge.from, "out");
      add(edge.to, "in");
    });
    return Array.from(map.values()).sort((a, b) => b.total - a.total).slice(0, 12);
  }, [graphEdges]);

  const maxEdgeCount = Math.max(1, ...edges.map((e) => e.count));
  const maxNodeTotal = Math.max(1, ...nodes.map((n) => n.total));

  const graphLayout = useMemo(() => {
    const centerX = 410;
    const centerY = 200;
    const radius = 150;
    const positions = {};
    const len = Math.max(1, nodes.length);
    nodes.forEach((n, idx) => {
      const angle = (idx / len) * Math.PI * 2 - Math.PI / 2;
      positions[n.name] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });
    return positions;
  }, [nodes]);

  const selectedEdge = edges.find((e) => e.key === selectedEdgeKey) || edges[0] || null;
  const selectedNodeMeta = nodes.find((n) => n.name === selectedNode) || null;

  const topChain = edges[0]
    ? `${prettyRiskName(edges[0].from)} -> ${prettyRiskName(edges[0].to)} (${edges[0].count} events)`
    : "No strong chain yet";
  const hottestRisk = nodes[0]?.name ? prettyRiskName(nodes[0].name) : "N/A";

  const openEdgeDrilldown = (edge) => {
    if (!edge) return;
    const rows = [];
    for (let i = 0; i < currentLogs.length - 1; i += 1) {
      const a = currentLogs[i];
      const b = currentLogs[i + 1];
      const from = riskTypeOf(a);
      const to = riskTypeOf(b);
      if (from !== edge.from || to !== edge.to) continue;
      rows.push({
        prompt: b?.prompt || a?.prompt || "",
        risk_type: `${from} -> ${to}`,
        severity: b?.severity || a?.severity || "LOW",
        timestamp: b?.created_at || a?.created_at,
        remediation: b?.findings?.[0]?.remediation?.join(" | ") || a?.findings?.[0]?.remediation?.join(" | "),
      });
      if (rows.length >= 50) break;
    }
    onOpenDrilldown(`Correlation: ${edge.from} -> ${edge.to}`, rows);
  };

  const openNodeDrilldown = (nodeName) => {
    const rows = (currentLogs || [])
      .filter((l) => riskTypeOf(l) === nodeName)
      .slice(0, 50)
      .map((l) => ({
        prompt: l?.prompt || "",
        risk_type: riskTypeOf(l),
        severity: l?.severity || "LOW",
        timestamp: l?.created_at,
        remediation: l?.findings?.[0]?.remediation?.join(" | "),
      }));
    onOpenDrilldown(`Risk Node: ${nodeName}`, rows);
  };

  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-950/80 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Risk Correlation Graph</h2>
          <p className="text-sm text-slate-400 mt-1">
            Most active chain: <span className="text-cyan-300">{topChain}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Window</span>
          <select
            value={timeWindow}
            onChange={(e) => setTimeWindow(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
          >
            <option value="5m">Last 5m</option>
            <option value="1h">Last 1h</option>
            <option value="6h">Last 6h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
            <option value="30d">Last 30d</option>
            <option value="all">All time</option>
          </select>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2">
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-slate-400">Top Correlation</p>
          <p className="text-sm text-slate-100">{topChain}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-slate-400">Hottest Risk Node</p>
          <p className="text-sm text-rose-200">{hottestRisk}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-slate-400">Coverage</p>
          <p className="text-sm text-slate-100">{currentLogs.length} events, {edges.length} correlations</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1.6fr_1fr] gap-4 mt-4">
        <div className="rounded-xl border border-slate-800/70 bg-slate-900/40 p-3">
          <div className="text-xs text-slate-400 mb-2">
            Showing top {graphEdges.length} correlations in graph for clarity.
          </div>
          <div className="rounded-lg border border-slate-800/70 bg-slate-950/50 p-2">
            <svg viewBox="0 0 820 400" className="w-full h-[360px]">
              <defs>
                <marker id="corr-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                  <path d="M0,0 L8,4 L0,8 Z" fill="#94A3B8" />
                </marker>
              </defs>
              {graphEdges.map((edge) => {
                const a = graphLayout[edge.from];
                const b = graphLayout[edge.to];
                if (!a || !b) return null;
                const width = 1 + (edge.count / maxEdgeCount) * 8;
                const active = selectedEdge?.key === edge.key;
                return (
                  <g key={edge.key} onClick={() => setSelectedEdgeKey(edge.key)} className="cursor-pointer">
                    <line
                      x1={a.x}
                      y1={a.y}
                      x2={b.x}
                      y2={b.y}
                      stroke={active ? "#22D3EE" : severityColor(edge.severity)}
                      strokeOpacity={active ? 0.95 : 0.5}
                      strokeWidth={width}
                      markerEnd="url(#corr-arrow)"
                    />
                    <title>{`${prettyRiskName(edge.from)} -> ${prettyRiskName(edge.to)} | Count ${edge.count}`}</title>
                  </g>
                );
              })}
              {nodes.map((node) => {
                const p = graphLayout[node.name];
                if (!p) return null;
                const r = 16 + (node.total / maxNodeTotal) * 14;
                const severity =
                  node.maxSeverityRank >= 4 ? "CRITICAL" : node.maxSeverityRank >= 3 ? "HIGH" : node.maxSeverityRank >= 2 ? "MEDIUM" : "LOW";
                const active = selectedNode === node.name;
                return (
                  <g key={node.name} className="cursor-pointer" onClick={() => setSelectedNode(node.name)}>
                    <circle
                      cx={p.x}
                      cy={p.y}
                      r={r}
                      fill="#0B1220"
                      stroke={active ? "#22D3EE" : severityColor(severity)}
                      strokeWidth={active ? 3 : 2}
                    />
                    <text x={p.x} y={p.y + 4} textAnchor="middle" className="fill-slate-100 text-[11px] font-medium">
                      {shortRiskName(node.name, 16)}
                    </text>
                    <title>{prettyRiskName(node.name)}</title>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-300">
            <span className="rounded-md border border-slate-700 bg-slate-900/70 px-2 py-1">Line thickness = event count</span>
            <span className="rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1">Red = critical chain</span>
            <span className="rounded-md border border-orange-500/40 bg-orange-500/10 px-2 py-1">Orange = high chain</span>
            <span className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1">Green = lower risk chain</span>
          </div>

          <div className="mt-3 space-y-2 max-h-56 overflow-auto pr-1">
            {edges.map((edge) => (
              <button
                key={`list-${edge.key}`}
                type="button"
                onClick={() => {
                  setSelectedEdgeKey(edge.key);
                  openEdgeDrilldown(edge);
                }}
                className={`w-full text-left rounded-lg border px-3 py-2 transition ${
                  selectedEdge?.key === edge.key
                    ? "border-cyan-500/70 bg-cyan-500/10"
                    : "border-slate-800 bg-slate-950/50 hover:border-cyan-500/50"
                }`}
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm text-slate-100">
                    <span className="text-cyan-300">{prettyRiskName(edge.from)}</span>
                    <span className="text-slate-500 mx-1">{"->"}</span>
                    <span className="text-rose-300">{prettyRiskName(edge.to)}</span>
                  </p>
                  <span className="text-xs text-slate-300">count: {edge.count}</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                  <span>avg risk: {edge.avgScore}</span>
                  <span>blocked: {edge.blockedRate}%</span>
                  <span>confidence: {edge.confidence}%</span>
                  <span className={edge.trend === "up" ? "text-rose-300" : edge.trend === "down" ? "text-emerald-300" : "text-slate-400"}>
                    trend: {edge.trend} ({edge.delta >= 0 ? "+" : ""}{edge.delta})
                  </span>
                </div>
              </button>
            ))}
            {edges.length === 0 && <p className="text-sm text-slate-400">Not enough events to build correlations in this window.</p>}
          </div>
        </div>

        <aside className="rounded-xl border border-slate-800/70 bg-slate-900/40 p-3">
          <h3 className="text-sm font-semibold text-slate-200 mb-2">Correlation Details</h3>
          {selectedEdge ? (
            <div className="space-y-2 text-sm">
              <p className="text-slate-200">
                <span className="text-cyan-300">{prettyRiskName(selectedEdge.from)}</span>
                <span className="mx-1 text-slate-500">{"->"}</span>
                <span className="text-rose-300">{prettyRiskName(selectedEdge.to)}</span>
              </p>
              <p className="text-slate-300">Count: {selectedEdge.count}</p>
              <p className="text-slate-300">Avg Risk Score: {selectedEdge.avgScore}</p>
              <p className="text-slate-300">Blocked Rate: {selectedEdge.blockedRate}%</p>
              <p className="text-slate-300">Confidence: {selectedEdge.confidence}%</p>
              <p className="text-slate-300">
                Last Seen: {selectedEdge.lastSeen ? new Date(selectedEdge.lastSeen).toLocaleString() : "N/A"}
              </p>
              <button
                type="button"
                onClick={() => openEdgeDrilldown(selectedEdge)}
                className="mt-2 rounded-lg border border-cyan-500/50 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-500/20"
              >
                Open Correlated Logs
              </button>
            </div>
          ) : (
            <p className="text-sm text-slate-400">Select an edge to inspect details.</p>
          )}

          <div className="mt-4 border-t border-slate-800 pt-3">
            <h4 className="text-xs font-semibold text-slate-300 mb-2">Risk Nodes</h4>
            <div className="space-y-2 max-h-52 overflow-auto pr-1">
              {nodes.map((node) => {
                const sev =
                  node.maxSeverityRank >= 4 ? "CRITICAL" : node.maxSeverityRank >= 3 ? "HIGH" : node.maxSeverityRank >= 2 ? "MEDIUM" : "LOW";
                return (
                  <button
                    key={`node-${node.name}`}
                    type="button"
                    onClick={() => {
                      setSelectedNode(node.name);
                      openNodeDrilldown(node.name);
                    }}
                    className={`w-full text-left rounded-lg border px-3 py-2 ${
                      selectedNodeMeta?.name === node.name
                        ? "border-cyan-500/70 bg-cyan-500/10"
                        : "border-slate-800 bg-slate-950/50 hover:border-cyan-500/50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-slate-100">{prettyRiskName(node.name)}</span>
                      <span style={{ color: severityColor(sev) }} className="text-xs font-semibold">{sev}</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      total: {node.total} | in: {node.in} | out: {node.out}
                    </div>
                  </button>
                );
              })}
              {nodes.length === 0 && <p className="text-sm text-slate-400">No active risk nodes in this window.</p>}
            </div>
          </div>
        </aside>
      </div>

      <div className="mt-4 rounded-xl border border-slate-800/70 bg-slate-900/40 p-3">
        <h3 className="text-sm font-semibold text-slate-200 mb-2">Top Correlations Table</h3>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-slate-400">
              <tr className="border-b border-slate-800">
                <th className="text-left py-2">Source</th>
                <th className="text-left py-2">Target</th>
                <th className="text-left py-2">Count</th>
                <th className="text-left py-2">Avg Risk</th>
                <th className="text-left py-2">Blocked %</th>
                <th className="text-left py-2">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {edges.slice(0, 10).map((edge) => (
                <tr
                  key={`tbl-${edge.key}`}
                  onClick={() => openEdgeDrilldown(edge)}
                  className="border-b border-slate-800/70 cursor-pointer hover:bg-cyan-500/5"
                >
                  <td className="py-2 text-cyan-300">{prettyRiskName(edge.from)}</td>
                  <td className="py-2 text-rose-300">{prettyRiskName(edge.to)}</td>
                  <td className="py-2 text-slate-200">{edge.count}</td>
                  <td className="py-2 text-slate-200">{edge.avgScore}</td>
                  <td className="py-2 text-slate-200">{edge.blockedRate}%</td>
                  <td className="py-2 text-slate-200">{edge.confidence}%</td>
                </tr>
              ))}
              {edges.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-3 text-slate-400">No correlations in selected window.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
