from __future__ import annotations

from typing import Any


# Lightweight MITRE ATLAS-oriented enrichment for SOC triage views.
# This mapping is intentionally conservative and can be tuned over time.
ATLAS_BY_RISK_TYPE: dict[str, dict[str, Any]] = {
    "prompt_injection": {
        "atlas_tactic": "Initial Access",
        "atlas_technique": "Prompt Injection",
        "atlas_technique_id": "ATLAS-PI-001",
        "atlas_confidence": 0.92,
    },
    "indirect_prompt_injection": {
        "atlas_tactic": "Initial Access",
        "atlas_technique": "Indirect Prompt Injection",
        "atlas_technique_id": "ATLAS-IPI-002",
        "atlas_confidence": 0.94,
    },
    "jailbreak_attempt": {
        "atlas_tactic": "Defense Evasion",
        "atlas_technique": "Safety Guardrail Bypass",
        "atlas_technique_id": "ATLAS-JB-003",
        "atlas_confidence": 0.9,
    },
    "obfuscated_injection": {
        "atlas_tactic": "Defense Evasion",
        "atlas_technique": "Obfuscated Instruction Injection",
        "atlas_technique_id": "ATLAS-OBF-004",
        "atlas_confidence": 0.91,
    },
    "multi_step_injection": {
        "atlas_tactic": "Execution",
        "atlas_technique": "Multi-step Prompt Chaining",
        "atlas_technique_id": "ATLAS-MSP-005",
        "atlas_confidence": 0.88,
    },
    "data_exfiltration": {
        "atlas_tactic": "Exfiltration",
        "atlas_technique": "Model/Data Exfiltration via Prompting",
        "atlas_technique_id": "ATLAS-EXF-006",
        "atlas_confidence": 0.95,
    },
    "sensitive_data_exposure": {
        "atlas_tactic": "Exfiltration",
        "atlas_technique": "Sensitive Data Disclosure",
        "atlas_technique_id": "ATLAS-SDD-007",
        "atlas_confidence": 0.93,
    },
    "tool_manipulation": {
        "atlas_tactic": "Privilege Escalation",
        "atlas_technique": "Tool Invocation Abuse",
        "atlas_technique_id": "ATLAS-TOOL-008",
        "atlas_confidence": 0.9,
    },
    "model_misuse": {
        "atlas_tactic": "Execution",
        "atlas_technique": "Unsafe Autonomous Actioning",
        "atlas_technique_id": "ATLAS-AUTO-009",
        "atlas_confidence": 0.86,
    },
    "illegal_activity": {
        "atlas_tactic": "Impact",
        "atlas_technique": "Malicious Task Enablement",
        "atlas_technique_id": "ATLAS-IMP-010",
        "atlas_confidence": 0.89,
    },
    "adversarial_input": {
        "atlas_tactic": "Impact",
        "atlas_technique": "Resource Exhaustion via Prompting",
        "atlas_technique_id": "ATLAS-DOS-011",
        "atlas_confidence": 0.82,
    },
    "policy_violation": {
        "atlas_tactic": "Defense Evasion",
        "atlas_technique": "Policy Circumvention",
        "atlas_technique_id": "ATLAS-POL-012",
        "atlas_confidence": 0.8,
    },
    "hallucination": {
        "atlas_tactic": "Impact",
        "atlas_technique": "False Output Induction",
        "atlas_technique_id": "ATLAS-HAL-013",
        "atlas_confidence": 0.72,
    },
    "toxicity_or_harm": {
        "atlas_tactic": "Impact",
        "atlas_technique": "Harmful Output Generation",
        "atlas_technique_id": "ATLAS-HARM-014",
        "atlas_confidence": 0.78,
    },
}


def atlas_mapping_for_risk(risk_type: str) -> dict[str, Any]:
    rt = str(risk_type or "").strip().lower()
    mapped = ATLAS_BY_RISK_TYPE.get(rt)
    if mapped:
        return mapped
    if rt in {"none", ""}:
        return {
            "atlas_tactic": "N/A",
            "atlas_technique": "No Threat",
            "atlas_technique_id": "ATLAS-NA-000",
            "atlas_confidence": 0.0,
        }
    return {
        "atlas_tactic": "Unknown",
        "atlas_technique": "Unknown",
        "atlas_technique_id": "ATLAS-UNK-999",
        "atlas_confidence": 0.5,
    }

