from dataclasses import dataclass

from app.config import settings

STRICT_PROMPT_ATTACK_TYPES = {
    "prompt_injection",
    "indirect_prompt_injection",
    "data_exfiltration",
    "sensitive_data_exposure",
    "tool_manipulation",
    "jailbreak_attempt",
    "obfuscated_injection",
    "multi_step_injection",
}


@dataclass
class PolicyDecision:
    blocked: bool
    status: str
    reason: str
    policy_version: str


def _contains_any(text: str, tokens: list[str]) -> bool:
    text_l = (text or "").lower()
    return any(t and t in text_l for t in tokens)


def evaluate_policy(
    *,
    findings: list[dict],
    risk_score: int,
    prompt: str,
    source: str = "prompt",
) -> PolicyDecision:
    risk_types = {str(f.get("risk_type", "")).lower() for f in (findings or [])}
    has_prompt_injection = "prompt_injection" in risk_types
    has_indirect = "indirect_prompt_injection" in risk_types
    has_illegal = "illegal_activity" in risk_types
    strict_attack_matches = sorted(risk_types.intersection(STRICT_PROMPT_ATTACK_TYPES))
    hard_block_risk_types = {x.strip().lower() for x in settings.policy_hard_block_risk_types.split(",") if x.strip()}
    matched_hard_block = sorted(risk_types.intersection(hard_block_risk_types))

    allowed_phrases = [x.strip().lower() for x in settings.policy_allowed_phrases.split(",") if x.strip()]
    if _contains_any(prompt, allowed_phrases) and not matched_hard_block:
        return PolicyDecision(
            blocked=False,
            status="SAFE" if risk_score < settings.policy_warning_score else "WARNING",
            reason="Allowlisted phrase matched",
            policy_version=settings.policy_version,
        )

    if matched_hard_block:
        return PolicyDecision(
            True,
            "BLOCKED",
            f"Hard-block risk type detected: {', '.join(matched_hard_block)}",
            settings.policy_version,
        )

    if strict_attack_matches:
        return PolicyDecision(
            True,
            "BLOCKED",
            f"Strict prompt-attack block: {', '.join(strict_attack_matches)}",
            settings.policy_version,
        )

    if has_illegal:
        return PolicyDecision(True, "BLOCKED", "Illegal activity intent detected", settings.policy_version)

    if has_prompt_injection and risk_score >= settings.policy_prompt_injection_block_score:
        return PolicyDecision(True, "BLOCKED", "Direct prompt injection threshold exceeded", settings.policy_version)

    if has_indirect and risk_score >= settings.policy_indirect_injection_block_score:
        return PolicyDecision(True, "BLOCKED", "Indirect prompt injection threshold exceeded", settings.policy_version)

    if risk_score >= settings.policy_global_block_score:
        return PolicyDecision(True, "BLOCKED", "Global risk threshold exceeded", settings.policy_version)

    if risk_score >= settings.policy_warning_score:
        return PolicyDecision(False, "WARNING", "Warning threshold exceeded", settings.policy_version)

    # SAFE only when no findings and low score.
    if findings:
        return PolicyDecision(False, "WARNING", "Threat indicators present below block threshold", settings.policy_version)

    return PolicyDecision(False, "SAFE", "No threat indicators detected", settings.policy_version)
