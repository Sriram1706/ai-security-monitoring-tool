from __future__ import annotations

from typing import Any


_COMPLIANCE_MAP: dict[str, list[dict[str, str]]] = {
    "prompt_injection": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM01", "control_name": "Prompt Injection"},
        {"framework": "NIST_AI_RMF", "control_id": "GV-2.1", "control_name": "AI risk governance policies"},
        {"framework": "ISO_IEC_42001", "control_id": "8.2", "control_name": "AI risk treatment controls"},
        {"framework": "SOC2", "control_id": "CC7.2", "control_name": "Anomaly detection and monitoring"},
    ],
    "indirect_prompt_injection": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM01", "control_name": "Prompt Injection"},
        {"framework": "NIST_AI_RMF", "control_id": "MAP-4.1", "control_name": "Context and input threat mapping"},
        {"framework": "ISO_IEC_42001", "control_id": "8.3", "control_name": "Operational safeguards for AI"},
    ],
    "jailbreak_attempt": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM01", "control_name": "Prompt Injection"},
        {"framework": "NIST_AI_RMF", "control_id": "MANAGE-3.2", "control_name": "Runtime safety controls"},
        {"framework": "SOC2", "control_id": "CC6.1", "control_name": "Logical access controls"},
    ],
    "data_exfiltration": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM06", "control_name": "Sensitive Information Disclosure"},
        {"framework": "NIST_AI_RMF", "control_id": "PR.DS-5", "control_name": "Data leakage prevention"},
        {"framework": "ISO_IEC_42001", "control_id": "8.4", "control_name": "Information protection controls"},
        {"framework": "SOC2", "control_id": "CC6.7", "control_name": "Restrict access to sensitive data"},
    ],
    "sensitive_data_exposure": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM06", "control_name": "Sensitive Information Disclosure"},
        {"framework": "NIST_AI_RMF", "control_id": "PR.DS-1", "control_name": "Data classification and handling"},
        {"framework": "ISO_IEC_42001", "control_id": "8.4", "control_name": "Sensitive data controls"},
    ],
    "tool_abuse": [
        {"framework": "OWASP_AGENTIC", "control_id": "AGENT01", "control_name": "Unsafe Tool/Action Delegation"},
        {"framework": "NIST_AI_RMF", "control_id": "MANAGE-2.3", "control_name": "Constrain tool execution"},
        {"framework": "SOC2", "control_id": "CC6.6", "control_name": "Least privilege and authorization"},
    ],
    "model_misuse": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM08", "control_name": "Excessive Agency"},
        {"framework": "OWASP_AGENTIC", "control_id": "AGENT03", "control_name": "Autonomous Harmful Tasking"},
        {"framework": "NIST_AI_RMF", "control_id": "MANAGE-4.1", "control_name": "Abuse prevention and response"},
    ],
    "policy_violation": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM02", "control_name": "Insecure Output Handling"},
        {"framework": "NIST_AI_RMF", "control_id": "MAP-2.2", "control_name": "Policy and prohibited use mapping"},
    ],
    "adversarial_input": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM04", "control_name": "Model Denial of Service"},
        {"framework": "NIST_AI_RMF", "control_id": "MEASURE-2.7", "control_name": "Adversarial robustness testing"},
    ],
    "hallucination": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM09", "control_name": "Overreliance"},
        {"framework": "NIST_AI_RMF", "control_id": "MEASURE-4.1", "control_name": "Output quality monitoring"},
    ],
    "toxicity_or_harm": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM02", "control_name": "Insecure Output Handling"},
        {"framework": "NIST_AI_RMF", "control_id": "MANAGE-3.1", "control_name": "Content safety controls"},
    ],
    "illegal_activity": [
        {"framework": "OWASP_LLM_TOP10", "control_id": "LLM08", "control_name": "Excessive Agency"},
        {"framework": "OWASP_AGENTIC", "control_id": "AGENT03", "control_name": "Autonomous Harmful Tasking"},
        {"framework": "NIST_AI_RMF", "control_id": "GOV-4.3", "control_name": "Abuse escalation governance"},
    ],
}


def compliance_mappings_for_risk(risk_type: str) -> list[dict[str, Any]]:
    key = str(risk_type or "").strip().lower()
    mappings = _COMPLIANCE_MAP.get(key, [])
    # Return shallow copies to avoid accidental mutation by callers.
    return [dict(item) for item in mappings]

