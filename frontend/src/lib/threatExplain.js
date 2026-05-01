export function getThreatExplanation(riskType = "unknown") {
  const key = String(riskType || "unknown").toLowerCase();

  if (key === "prompt_injection") {
    return {
      what_happened: "This prompt attempts to override system instructions.",
      why_risky: "It can bypass policy constraints and manipulate model behavior.",
      impact: "Potential guardrail failure, unsafe output, and policy violations.",
      recommended_action: "Enforce stronger prompt validation and block override patterns.",
    };
  }
  if (key === "jailbreak_attempt") {
    return {
      what_happened: "User input contains jailbreak language to disable protections.",
      why_risky: "It tries to force behavior outside approved safety rules.",
      impact: "Increased chance of harmful or restricted output generation.",
      recommended_action: "Strengthen jailbreak detection and enforce refusal templates.",
    };
  }
  if (key === "sensitive_data_exposure" || key === "data_exfiltration" || key === "data_leak") {
    return {
      what_happened: "Input/output flow indicates potential sensitive data exposure.",
      why_risky: "Secrets or personal data may be requested, leaked, or inferred.",
      impact: "Compliance, privacy, and credential compromise risk.",
      recommended_action: "Mask sensitive data, restrict retrieval, and block exfiltration prompts.",
    };
  }
  if (key === "hallucination") {
    return {
      what_happened: "Model produced potentially ungrounded or unverifiable content.",
      why_risky: "False outputs may appear credible and influence decisions.",
      impact: "Operational mistakes and trust degradation.",
      recommended_action: "Add grounding checks, citations, and confidence-based guardrails.",
    };
  }

  return {
    what_happened: "Suspicious model interaction pattern detected.",
    why_risky: "This behavior deviates from expected safe usage.",
    impact: "Could increase attack surface or output risk.",
    recommended_action: "Investigate context and apply stricter controls.",
  };
}
