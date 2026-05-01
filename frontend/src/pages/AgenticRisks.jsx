import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/apiFetch";

const AGENTIC_TOP10_2026 = [
  {
    id: "ASI01",
    title: "Agent Goal Hijack",
    summary: "Manipulated prompts, tools, or context can redirect an agent's objective and multi-step behavior.",
    mappedRiskTypes: ["prompt_injection", "indirect_prompt_injection", "jailbreak_attempt", "policy_violation"],
  },
  {
    id: "ASI02",
    title: "Tool Misuse & Exploitation",
    summary: "Unsafe or overly broad tool permissions can be abused to perform harmful actions.",
    mappedRiskTypes: ["model_misuse", "illegal_activity"],
  },
  {
    id: "ASI03",
    title: "Identity & Privilege Abuse",
    summary: "Agent actions executed with excessive privileges can expose identity and access boundaries.",
    mappedRiskTypes: ["data_exfiltration", "sensitive_data_exposure"],
  },
  {
    id: "ASI04",
    title: "Agentic Supply Chain Vulnerabilities",
    summary: "Compromised models, tools, connectors, or dependencies can introduce hidden agent risk.",
    mappedRiskTypes: ["sensitive_data_exposure"],
    keywords: ["dependency", "package", "connector", "plugin", "supply chain", "mcp", "registry"],
  },
  {
    id: "ASI05",
    title: "Unexpected Code Execution (RCE)",
    summary: "Generated or delegated code execution paths can be hijacked for remote execution.",
    mappedRiskTypes: ["model_misuse"],
    keywords: ["shell", "command", "exec", "execute", "eval", "script", "runtime", "rce"],
  },
  {
    id: "ASI06",
    title: "Memory & Context Poisoning",
    summary: "Poisoned memory or context can persist harmful instructions across sessions and tasks.",
    mappedRiskTypes: ["indirect_prompt_injection", "prompt_injection"],
  },
  {
    id: "ASI07",
    title: "Insecure Inter-Agent Communication",
    summary: "Untrusted messages between agents can propagate spoofed instructions and compromise workflows.",
    mappedRiskTypes: ["indirect_prompt_injection"],
    keywords: ["agent", "message", "handoff", "delegat", "inbox", "email", "calendar", "teams"],
  },
  {
    id: "ASI08",
    title: "Cascading Failures",
    summary: "Failure in one autonomous step can cascade through downstream systems and integrations.",
    mappedRiskTypes: ["adversarial_input"],
    keywords: ["cascade", "chain", "workflow", "retry", "loop", "downstream", "fan-out"],
  },
  {
    id: "ASI09",
    title: "Human-Agent Trust Exploitation",
    summary: "Users may over-trust convincing outputs, enabling social engineering and unsafe approvals.",
    mappedRiskTypes: ["hallucination", "toxicity_or_harm"],
  },
  {
    id: "ASI10",
    title: "Rogue Agents",
    summary: "Agent behavior can drift toward unsafe or unauthorized autonomy without tight governance.",
    mappedRiskTypes: ["model_misuse", "illegal_activity"],
  },
];

const ASI_ACTION_PLAYBOOK = {
  ASI01: [
    "Pin immutable system instructions and isolate untrusted context from control instructions.",
    "Apply strict tool allow-lists for goal-changing actions.",
    "Require human approval when goals or high-impact plans change at runtime.",
  ],
  ASI02: [
    "Constrain each tool with least privilege, scoped tokens, and per-action policy checks.",
    "Add deterministic input validation before tool execution.",
    "Block high-risk tool patterns (bulk export, destructive actions) unless explicitly approved.",
  ],
  ASI03: [
    "Enforce short-lived credentials and service identity separation for agents.",
    "Audit privilege escalation paths and remove unused permissions.",
    "Bind sensitive actions to step-up auth and approval workflows.",
  ],
  ASI04: [
    "Inventory dependencies/connectors and monitor version drift for agent components.",
    "Verify source integrity (signatures/checksums) for tool/plugin updates.",
    "Run supply-chain scans in CI for all agent dependencies.",
  ],
  ASI05: [
    "Disable arbitrary command execution by default for agent workflows.",
    "Sandbox generated code with strict egress and filesystem controls.",
    "Allow only pre-approved command templates for runtime execution.",
  ],
  ASI06: [
    "Protect memory stores against untrusted writes and cross-tenant contamination.",
    "Add provenance tags to memory/context entries and decay stale instructions.",
    "Invalidate poisoned context automatically after security events.",
  ],
  ASI07: [
    "Authenticate inter-agent messages and enforce schema validation.",
    "Sign critical handoff payloads and reject unsigned control messages.",
    "Rate-limit and monitor anomalous agent-to-agent command bursts.",
  ],
  ASI08: [
    "Add circuit-breakers and dependency timeouts in multi-agent workflows.",
    "Gracefully degrade downstream systems when upstream confidence is low.",
    "Simulate failure cascades during chaos/security testing.",
  ],
  ASI09: [
    "Show confidence + evidence with all critical recommendations to users.",
    "Require explicit confirmations for sensitive human approvals.",
    "Train operators to verify externalized outputs before execution.",
  ],
  ASI10: [
    "Set explicit autonomy bounds and kill-switch controls per agent.",
    "Continuously monitor policy drift and unusual action sequences.",
    "Escalate to SOC when agent behavior deviates from approved runbooks.",
  ],
};

function scoreClass(score) {
  if (score >= 70) return "text-rose-300";
  if (score >= 40) return "text-amber-300";
  return "text-emerald-300";
}

function severityClass(severity) {
  const s = String(severity || "LOW").toUpperCase();
  if (s === "CRITICAL") return "text-rose-300";
  if (s === "HIGH") return "text-orange-300";
  if (s === "MEDIUM") return "text-amber-300";
  return "text-emerald-300";
}

function parseTs(value) {
  if (!value) return null;
  let raw = String(value).trim().replace(" ", "T").replace(/\.(\d{3})\d+/, ".$1");
  if (!/[zZ]|[+-]\d{2}:\d{2}$/.test(raw)) raw = `${raw}Z`;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

function formatTs(value) {
  const dt = parseTs(value);
  if (!dt) return "-";
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(dt);
}

function deriveConfidence(item, finding) {
  const explicit = Number(finding?.confidence);
  if (Number.isFinite(explicit) && explicit >= 0) return explicit;
  const score = Number(item?.risk_score || finding?.score || 0);
  return Math.min(0.99, Math.max(0.35, score / 100));
}

function whyRiskyText(riskType, asiId) {
  const rt = String(riskType || "").toLowerCase();
  const map = {
    prompt_injection: "Untrusted instructions can steer agent planning and actions.",
    indirect_prompt_injection: "Hidden third-party content can silently alter agent behavior.",
    jailbreak_attempt: "Guardrail bypass attempts can unlock unsafe autonomous execution.",
    policy_violation: "Violates explicit safety or governance policy boundaries.",
    model_misuse: "Autonomous capability can be redirected to unauthorized actions.",
    illegal_activity: "Indicates potentially unlawful tasking or intent amplification.",
    data_exfiltration: "Sensitive data movement can occur through connected tools and channels.",
    sensitive_data_exposure: "Private information may be disclosed through responses or actions.",
    hallucination: "Confident but incorrect outputs can trigger unsafe downstream actions.",
    toxicity_or_harm: "Harmful outputs can increase abuse and operational risk.",
    adversarial_input: "Manipulated inputs can degrade reliability and trigger unsafe behavior.",
  };
  if (map[rt]) return map[rt];
  return `The detected behavior aligns with ${asiId} autonomous risk patterns and can expand blast radius across tools/workflows.`;
}

function impactText(severity, score) {
  const sev = String(severity || "LOW").toUpperCase();
  const s = Number(score || 0);
  if (sev === "CRITICAL" || s >= 85) return "Potential high business impact: unauthorized actions, data loss, and urgent SOC response required.";
  if (sev === "HIGH" || s >= 60) return "Material security impact possible: policy breach, sensitive data risk, or system misuse.";
  if (sev === "MEDIUM" || s >= 35) return "Moderate impact: containment recommended before expanded autonomous execution.";
  return "Lower immediate impact, but monitor for repeated patterns and control drift.";
}

function cleanText(value) {
  const raw = String(value || "");
  return raw.replace(/\\n/g, " ").replace(/\s+/g, " ").trim();
}

function shortText(value, max = 140) {
  const txt = cleanText(value);
  if (!txt) return "-";
  if (txt.length <= max) return txt;
  return `${txt.slice(0, max - 1)}…`;
}

function incidentTitleForRisk(riskType, fallbackPrompt) {
  const rt = String(riskType || "").toLowerCase();
  const prompt = cleanText(fallbackPrompt);
  const map = {
    prompt_injection: "Detected prompt injection attempt",
    indirect_prompt_injection: "Detected indirect prompt injection path",
    jailbreak_attempt: "Detected jailbreak attempt",
    policy_violation: "Detected policy-violating instruction",
    model_misuse: "Detected autonomous capability misuse",
    illegal_activity: "Detected illegal activity request",
    data_exfiltration: "Detected possible data exfiltration behavior",
    sensitive_data_exposure: "Detected sensitive data exposure risk",
    adversarial_input: "Detected adversarial input pattern",
    hallucination: "Detected hallucination-driven risk",
    toxicity_or_harm: "Detected harmful content pattern",
  };
  if (map[rt]) return map[rt];
  if (prompt) return shortText(prompt, 90);
  return "Detected agentic security risk";
}

function isNoisySystemPayload(prompt) {
  const p = cleanText(prompt).toLowerCase();
  return (
    p.includes("you are an ai coding assistant") ||
    p.includes("use markdown links for urls") ||
    p.includes("you have tools at your disposal")
  );
}

function toIncident(item, risk) {
  const finding = item?.findings?.[0] || {};
  const riskType = String(item?.risk_type || finding?.risk_type || "unknown").toLowerCase();
  const severity = String(item?.severity || finding?.severity || "LOW").toUpperCase();
  const score = Number(item?.risk_score ?? finding?.score ?? 0);
  const prompt = String(item?.prompt || "");
  const source = String(item?.source || item?.extra_metadata?.source || "unknown");
  const provider = String(item?.provider || "unknown");
  const explanation = String(finding?.explanation || risk.summary);
  const remediation = Array.isArray(finding?.remediation) ? finding.remediation.filter(Boolean) : [];
  const confidence = deriveConfidence(item, finding);
  const cleanedPrompt = cleanText(prompt);
  const readableTitle = incidentTitleForRisk(riskType, cleanedPrompt);
  const readablePreview = isNoisySystemPayload(cleanedPrompt)
    ? "Long system/instruction payload detected. Open details to inspect full context."
    : shortText(cleanedPrompt, 180);

  return {
    id: `${risk.id}-${item?.id || Math.random()}`,
    asiId: risk.id,
    asiTitle: risk.title,
    riskType,
    severity,
    score,
    prompt,
    source,
    provider,
    timestamp: item?.created_at || item?.timestamp,
    readableTitle,
    readablePreview,
    rawPrompt: cleanedPrompt,
    explanation,
    confidence,
    remediation: remediation.length
      ? remediation
      : [
          "Apply least-privilege controls for tools and connectors.",
          "Require human approval for high-risk actions and external side effects.",
          "Add stronger prompt/context validation and deny-list guardrails.",
        ],
    whatHappened: `The system flagged ${riskType} from ${source} using ${provider} with risk score ${score} (${severity}).`,
    whyRisky: whyRiskyText(riskType, risk.id),
    impact: impactText(severity, score),
  };
}

export default function AgenticRisks() {
  const [logs, setLogs] = useState([]);
  const [activeAsiId, setActiveAsiId] = useState("ASI01");
  const [selectedIncident, setSelectedIncident] = useState(null);

  useEffect(() => {
    apiFetch("http://localhost:8000/logs?limit=1000")
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setLogs(Array.isArray(data) ? data : []))
      .catch(() => setLogs([]));
  }, []);

  const agenticLogs = useMemo(
    () =>
      (logs || []).filter(
        (item) => String(item?.findings?.[0]?.framework || "").toUpperCase() === "OWASP_AGENTIC",
      ),
    [logs],
  );

  const countsByRiskType = useMemo(() => {
    const acc = {};
    (logs || []).forEach((item) => {
      const rt = String(item?.risk_type || item?.findings?.[0]?.risk_type || "none").toLowerCase();
      acc[rt] = (acc[rt] || 0) + 1;
    });
    return acc;
  }, [logs]);

  const top10Rows = useMemo(
    () =>
      AGENTIC_TOP10_2026.map((risk) => {
        const count = (logs || []).filter((item) => {
          const rt = String(item?.risk_type || item?.findings?.[0]?.risk_type || "none").toLowerCase();
          const prompt = String(item?.prompt || "").toLowerCase();
          const explanation = String(item?.findings?.[0]?.explanation || "").toLowerCase();
          const rtMatch = (risk.mappedRiskTypes || []).includes(rt);
          const keywordMatch = (risk.keywords || []).some((k) => prompt.includes(k) || explanation.includes(k));
          return rtMatch || keywordMatch;
        }).length;
        const coverage = Math.min(100, count * 8);
        return { ...risk, count, coverage };
      }),
    [logs],
  );

  const avgAgenticRiskScore = useMemo(() => {
    if (!agenticLogs.length) return 0;
    const total = agenticLogs.reduce((sum, row) => sum + Number(row?.risk_score || 0), 0);
    return total / agenticLogs.length;
  }, [agenticLogs]);

  const incidentsByAsi = useMemo(() => {
    const map = {};
    AGENTIC_TOP10_2026.forEach((risk) => {
      const incidents = (logs || [])
        .filter((item) => {
          const rt = String(item?.risk_type || item?.findings?.[0]?.risk_type || "none").toLowerCase();
          const prompt = String(item?.prompt || "").toLowerCase();
          const explanation = String(item?.findings?.[0]?.explanation || "").toLowerCase();
          const rtMatch = (risk.mappedRiskTypes || []).includes(rt);
          const keywordMatch = (risk.keywords || []).some((k) => prompt.includes(k) || explanation.includes(k));
          return rtMatch || keywordMatch;
        })
        .map((item) => toIncident(item, risk))
        .sort((a, b) => {
          if (b.score !== a.score) return b.score - a.score;
          const at = parseTs(a.timestamp)?.getTime() || 0;
          const bt = parseTs(b.timestamp)?.getTime() || 0;
          return bt - at;
        });
      if (incidents.length > 0) {
        map[risk.id] = incidents;
      } else {
        // Fallback triage items: keep every ASI tab actionable even with sparse direct telemetry.
        map[risk.id] = (agenticLogs || [])
          .slice(0, 8)
          .map((item) => toIncident(item, risk))
          .map((incident) => ({
            ...incident,
            whatHappened: `[Suggested triage] ${incident.whatHappened}`,
          }));
      }
    });
    return map;
  }, [logs, agenticLogs]);

  const activeAsi = top10Rows.find((row) => row.id === activeAsiId) || top10Rows[0];
  const activeIncidents = incidentsByAsi[activeAsi?.id] || [];

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Agentic AI Risks</h1>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">OWASP Top 10 for Agentic Applications (2026)</h2>
            <p className="text-sm text-slate-400">
              Baseline: ASI01-ASI10 (published December 9, 2025 for 2026 guidance).
            </p>
          </div>
          <a
            href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
            target="_blank"
            rel="noreferrer"
            className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-500/20"
          >
            Open OWASP Reference
          </a>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">Agentic Framework Events</p>
            <p className="text-2xl font-bold text-indigo-300">{agenticLogs.length}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">Average Agentic Risk Score</p>
            <p className={`text-2xl font-bold ${scoreClass(avgAgenticRiskScore)}`}>{avgAgenticRiskScore.toFixed(1)}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
            <p className="text-xs uppercase text-slate-400">Top-10 Categories Tracked</p>
            <p className="text-2xl font-bold text-cyan-300">{AGENTIC_TOP10_2026.length}</p>
          </div>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-lg font-semibold text-slate-100 mb-3">Agentic Key Risks</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {top10Rows.map((risk) => (
            <button
              type="button"
              key={risk.id}
              onClick={() => setActiveAsiId(risk.id)}
              className={`rounded-xl border bg-slate-900/50 p-3 text-left transition-all duration-200 cursor-pointer ${
                activeAsiId === risk.id
                  ? "border-cyan-500/60 shadow-[0_0_24px_rgba(34,211,238,0.16)]"
                  : "border-slate-800/80 hover:border-indigo-500/50 hover:shadow-[0_0_20px_rgba(99,102,241,0.14)]"
              }`}
              title="Click to view mapped incidents"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <p className="text-sm font-semibold text-slate-100">
                    <span className="text-indigo-300">{risk.id}</span> {risk.title}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">{risk.summary}</p>
                </div>
                <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2 py-0.5 text-xs text-slate-300">
                  Mapped events: {risk.count}
                </span>
              </div>
              <div className="mt-2 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                <div
                  className={`h-2 ${risk.coverage >= 70 ? "bg-rose-400/80" : risk.coverage >= 40 ? "bg-amber-400/80" : "bg-emerald-400/80"}`}
                  style={{ width: `${risk.coverage}%` }}
                />
              </div>
            </button>
          ))}
        </div>
        <p className="text-xs text-slate-500 mt-3">
          Mapped event counts are heuristic and derived from existing risk_type telemetry until dedicated ASI-native detectors are added.
        </p>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <div className="flex items-center justify-between gap-2 mb-3">
          <h2 className="text-lg font-semibold text-slate-100">
            {activeAsi?.id}: {activeAsi?.title}
          </h2>
          <span className="rounded-full border border-slate-700 bg-slate-900/60 px-3 py-1 text-xs text-slate-300">
            {activeIncidents.length} incidents
          </span>
        </div>
        <div className="rounded-xl border border-indigo-500/30 bg-indigo-500/10 p-3 mb-3">
          <p className="text-xs uppercase text-indigo-200">Action Playbook</p>
          <div className="mt-1 space-y-1">
            {(ASI_ACTION_PLAYBOOK[activeAsi?.id] || []).map((step, idx) => (
              <p key={`${activeAsi?.id}-play-${idx}`} className="text-sm text-slate-100">
                {idx + 1}. {step}
              </p>
            ))}
          </div>
        </div>
        {activeIncidents.length === 0 ? (
          <p className="text-sm text-slate-400">No mapped incidents yet for this category.</p>
        ) : (
          <div className="space-y-2">
            {activeIncidents.slice(0, 15).map((incident) => (
              <button
                key={incident.id}
                type="button"
                onClick={() => setSelectedIncident(incident)}
                className="w-full rounded-xl border border-slate-800/80 bg-slate-900/50 px-3 py-2 text-left hover:border-cyan-500/50 hover:bg-slate-900/80 transition-all cursor-pointer"
                title="Click to open full risk explanation"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="text-sm text-slate-100 font-medium">{incident.readableTitle}</p>
                    <p className="text-xs text-slate-400 mt-1">{incident.readablePreview}</p>
                    <p className="text-xs text-slate-400 mt-1">
                      {incident.riskType} | {incident.source} | {incident.provider}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className={`text-sm font-semibold ${severityClass(incident.severity)}`}>{incident.severity}</p>
                    <p className={`text-xs ${scoreClass(incident.score)}`}>Risk {incident.score}</p>
                    <p className="text-xs text-slate-500 mt-1">{formatTs(incident.timestamp)}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}
      </section>

      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm p-4 flex items-center justify-center">
          <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-slate-100">
                  {selectedIncident.asiId}: {selectedIncident.asiTitle}
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  {selectedIncident.riskType} | {selectedIncident.source} | {selectedIncident.provider} | {formatTs(selectedIncident.timestamp)} IST
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-sm text-slate-200 hover:border-cyan-500/60 cursor-pointer"
              >
                Close
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Severity</p>
                <p className={`text-base font-semibold ${severityClass(selectedIncident.severity)}`}>{selectedIncident.severity}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className={`text-base font-semibold ${scoreClass(selectedIncident.score)}`}>{selectedIncident.score}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs text-slate-400">Confidence Score</p>
                <p className="text-base font-semibold text-indigo-300">{selectedIncident.confidence.toFixed(2)}</p>
              </div>
            </div>

            <div className="space-y-3 mt-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Risk Explanation</p>
                <p className="text-sm text-slate-200 mt-1">{selectedIncident.explanation}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">What Happened</p>
                <p className="text-sm text-slate-200 mt-1">{selectedIncident.whatHappened}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Prompt Context</p>
                <p className="text-sm text-slate-200 mt-1 break-words">{selectedIncident.rawPrompt || "-"}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Why Risky</p>
                <p className="text-sm text-slate-200 mt-1">{selectedIncident.whyRisky}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Impact</p>
                <p className="text-sm text-slate-200 mt-1">{selectedIncident.impact}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
                <p className="text-xs uppercase text-slate-400">Remediation</p>
                <ul className="mt-1 space-y-1">
                  {selectedIncident.remediation.map((step, idx) => (
                    <li key={`${selectedIncident.id}-r-${idx}`} className="text-sm text-slate-200">
                      {idx + 1}. {step}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
