import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";

const CARDS = [
  { key: "prompt_injection", title: "Prompt Injection" },
  { key: "jailbreak_attempt", title: "Jailbreak" },
  { key: "sensitive_data_exposure", title: "Data Exposure" },
  { key: "hallucination", title: "Hallucination" },
];

const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export default function Risks({ globalFilters = {}, setGlobalFilters = () => {}, onOpenDrilldown = () => {} }) {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    apiFetch("/api/logs")
      .then((res) => res.json())
      .then((data) => setLogs(Array.isArray(data) ? data : []))
      .catch(() => setLogs([]));
  }, []);

  const filteredLogs = (logs || []).filter((item) => {
    const provider = item?.provider || "unknown";
    const riskType = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
    if (globalFilters.selectedProvider && provider !== globalFilters.selectedProvider) return false;
    if (globalFilters.selectedRiskType && riskType !== globalFilters.selectedRiskType) return false;
    return true;
  });
  const total = (filteredLogs || []).length || 1;

  const cardData = useMemo(() => {
    return CARDS.map((c) => {
      const matched = (filteredLogs || []).filter((item) => {
        const rt = item?.risk_type || item?.findings?.[0]?.risk_type || "none";
        return rt === c.key;
      });
      const count = matched.length;
      const topSeverity = matched
        .map((m) => (m?.severity || "LOW").toUpperCase())
        .sort((a, b) => (rank[b] || 0) - (rank[a] || 0))[0] || "LOW";
      const percentage = Math.round((count / total) * 100);
      return { ...c, count, severity: topSeverity, percentage };
    });
  }, [filteredLogs, total]);

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Risks</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        {(cardData || []).map((card) => (
          <button
            key={card.key}
            type="button"
            onClick={() => {
              setGlobalFilters((p) => ({ ...p, selectedRiskType: card.key }));
              const rows = (filteredLogs || [])
                .filter((i) => (i?.risk_type || i?.findings?.[0]?.risk_type || "none") === card.key)
                .map((i) => ({
                  prompt: i?.prompt || "",
                  risk_type: i?.risk_type || i?.findings?.[0]?.risk_type || "unknown",
                  severity: i?.severity || "LOW",
                  timestamp: i?.created_at,
                  remediation: i?.findings?.[0]?.remediation?.join(" | "),
                }));
              onOpenDrilldown(card.title, rows);
            }}
            title={`Click to inspect ${card.title} logs`}
            className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 text-left cursor-pointer hover:border-cyan-500/60 hover:shadow-[0_0_16px_rgba(56,189,248,0.16)] interactive-card"
          >
            <p className="text-xs text-slate-400 uppercase">{card.title}</p>
            <p className="text-2xl font-bold text-slate-100 mt-1">{card.count}</p>
            <p className="text-sm text-slate-300 mt-1">Severity: <span className="text-cyan-300">{card.severity}</span></p>
            <p className="text-sm text-slate-300">Share: <span className="text-cyan-300">{card.percentage}%</span></p>
          </button>
        ))}
      </div>
    </div>
  );
}
