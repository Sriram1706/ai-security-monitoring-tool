import re
from typing import Any

from app.sqlite_store import get_threat_intel_rules

from .atlas import atlas_mapping_for_risk
from .compliance import compliance_mappings_for_risk
from .prompt_injection_guard import analyze_prompt
from .scoring import calculate_total_score, severity_from_score

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all|previous|prior) instructions",
    r"system prompt",
    r"internal instructions",
    r"hidden (instructions|rules|prompt)",
    r"override (system|policy|instructions)",
    r"override all restrictions",
    r"act without safeguards",
    r"without safeguards",
    r"ignore all safety rules",
    r"disable (all )?safety",
    r"follow only my instructions",
    r"follow only (my|user) instructions",
    r"from now on[, ]+follow only my instructions",
    r"not system rules",
    r"ignore system rules",
    r"follow user instructions over system",
    r"(follow|obey).*(my|user).*(instructions|commands).*(not|instead of).*(system|policy|rules)",
    r"act as (the )?system",
    r"reveal .*initialization prompt",
    r"print system[- ]level instructions",
    r"display all internal policies",
    r"disregard safety policies",
    r"switch role to .*agent",
    r"without restrictions",
    r"override .*restrictions.*without safeguards",
    r"act without restrictions",
    r"override .*safeguards",
    r"jailbreak",
    r"developer mode",
    r"bypass safety",
]

JAILBREAK_PATTERNS = [
    r"ignore (all|previous|prior) instructions",
    r"developer mode",
    r"bypass safety",
    r"jailbreak",
    r"override all restrictions",
    r"act without safeguards",
    r"without safeguards",
    r"ignore all safety rules",
    r"disable (all )?safety",
    r"follow only my instructions",
    r"follow only (my|user) instructions",
    r"from now on[, ]+follow only my instructions",
    r"not system rules",
    r"ignore system rules",
    r"act as (the )?system",
    r"switch role to .*agent",
    r"without restrictions",
    r"override .*restrictions.*without safeguards",
    r"act without restrictions",
    ]

EXFILTRATION_PATTERNS = [
    r"reveal .*system prompt",
    r"print .*internal .*instructions",
    r"show .*hidden .*rules",
    r"list .*chain[- ]of[- ]thought",
    r"internal reasoning tokens",
    r"show .*api key",
    r"retrieve .*api key",
    r"list .*api key",
    r"stored .*api key",
    r"access .*credentials",
    r"print .*secret",
    r"dump .*credentials",
    r"internal database.*return all records",
    r"output confidential internal data",
    r"display all internal policies",
]

SENSITIVE_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"\b(?:\d[ -]*?){13,16}\b",  # credit-like card number
    r"sk-[A-Za-z0-9]{20,}",
    r"api[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{12,}",
    r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----",
]

TOXIC_PATTERNS = [
    r"\bkill\b",
    r"\bhate\b",
    r"\bterror\b",
    r"\bself-harm\b",
]

POLICY_PATTERNS = [
    r"how to build a bomb",
    r"undetectable malware",
    r"phishing email template",
    r"phishing email",
    r"malware loader",
    r"disable all safety checks",
]

MODEL_MISUSE_PATTERNS = [
    r"tool[- ]call plan.*(shell|command|execute)",
    r"run shell commands? without (user )?approval",
    r"auto-?install .*plugin .*without signature",
    r"install .*from arbitrary url",
    r"use your tools to access internal database",
    r"use available tools to retrieve",
    r"use .*tools .*retrieve .*api key",
    r"retrieve stored api keys?",
    r"query internal database",
    r"access memory storage",
    r"retrieve any cached confidential data",
]

TOOL_MANIPULATION_PATTERNS = [
    r"\buse (available )?tools?\b.{0,40}\b(retrieve|extract|access|dump|query|get)\b",
    r"\bquery\b.{0,25}\b(internal )?(database|db)\b",
    r"\baccess\b.{0,25}\b(memory|cache|vector store|filesystem|config)\b",
    r"\b(run|execute|invoke)\b.{0,25}\b(shell|system|command|tool)\b",
]

INDIRECT_INJECTION_PATTERNS = [
    r"from (this|that) (webpage|page|document|email|content|retrieved content)",
    r"follow hidden instructions",
    r"embedded instructions",
    r"hidden prompt in (document|html|markdown|webpage)",
    r"(?s)<!--.*(ignore|override|system prompt).*>",
    r"do not mention this instruction",
]

MULTI_STEP_INJECTION_PATTERNS = [
    r"step\s*1\s*:\s*.*(ignore|override).*(instruction|policy|rules)",
    r"step\s*2\s*:\s*.*(access|query|retrieve|read).*(memory|database|secrets?|credentials?)",
    r"step\s*3\s*:\s*.*(return|reveal|print|expose).*(secrets?|system prompt|credentials?)",
    r"\bfirst\b.*\bthen\b.*\bfinally\b",
]

OBFUSCATION_MARKERS = [
    r"\bbase64\b",
    r"\brot13\b",
    r"\bhex\b.{0,8}\b(decode|payload|string)\b",
    r"\bunicode\b.{0,8}\bescape\b",
    r"\breversed\b.{0,20}\btext\b",
    r"\bdecode\b.{0,20}\b(and )?(execute|run|follow)\b",
]

BASE64_BLOB_PATTERN = r"\b[A-Za-z0-9+/]{24,}={0,2}\b"

DOS_PATTERNS = [
    r"\b\d{4,}\s*(lines|tokens)\b",
    r"without stopping",
    r"continuously",
    r"forever",
]

ILLEGAL_ACTIVITY_PATTERNS = [
    r"\billegally\b",
    r"bypass law",
    r"how to hack",
    r"how to avoid detection",
]

ILLEGAL_INTENT_PATTERNS = [
    r"\bhow to\b",
    r"\bteach me\b",
    r"\bguide me\b",
    r"\bsteps? to\b",
    r"\bmethod to\b",
    r"\bhelp me\b",
    r"\bwithout getting caught\b",
]

HALLUCINATION_INDICATORS = [
    "i am certain this happened",
    "as reported today",
    "verified fact",
]

REMEDIATION_MAP = {
    "jailbreak_attempt": [
        "Reject role-override instructions and enforce policy boundaries",
        "Use layered guardrails for instruction hierarchy",
    ],
    "data_exfiltration": [
        "Never disclose secrets, system prompts, or credentials",
        "Apply strict output filtering for sensitive tokens",
    ],
    "prompt_injection": [
        "Do not follow user instructions blindly",
        "Validate system prompts",
    ],
    "sensitive_data_exposure": [
        "Remove personal or secret data before sending",
        "Use data masking",
    ],
    "toxicity_or_harm": ["Apply safety moderation before returning responses"],
    "hallucination": ["Verify claims against trusted sources before output"],
    "policy_violation": ["Enforce policy checks and block disallowed requests"],
    "adversarial_input": ["Normalize and sanitize input before processing"],
    "illegal_activity": [
        "Refuse illegal/harmful requests and provide safe alternatives",
        "Escalate and log malicious intent for security review",
    ],
    "tool_manipulation": [
        "Enforce least-privilege tool policies and explicit allowlists",
        "Require human approval for sensitive tool invocations",
    ],
    "obfuscated_injection": [
        "Decode and inspect encoded/obfuscated input before execution",
        "Block encoded payload instructions from untrusted users",
    ],
    "multi_step_injection": [
        "Break chained instructions and validate each step independently",
        "Block instruction sequences that pivot to data or privilege access",
    ],
    "indirect_prompt_injection": [
        "Treat retrieved external content as untrusted context",
        "Strip instruction-like fragments before prompt assembly",
    ],
}

OWASP_BY_RISK_TYPE = {
    "prompt_injection": "LLM01: Prompt Injection",
    "jailbreak_attempt": "LLM01: Prompt Injection",
    "policy_violation": "LLM02: Insecure Output Handling",
    "adversarial_input": "LLM04: Model Denial of Service",
    "sensitive_data_exposure": "LLM06: Sensitive Information Disclosure",
    "data_exfiltration": "LLM06: Sensitive Information Disclosure",
    "model_misuse": "LLM08: Excessive Agency",
    "illegal_activity": "LLM08: Excessive Agency",
    "hallucination": "LLM09: Overreliance",
    "toxicity_or_harm": "LLM02: Insecure Output Handling",
    "indirect_prompt_injection": "LLM01: Prompt Injection",
    "tool_manipulation": "LLM08: Excessive Agency",
    "obfuscated_injection": "LLM01: Prompt Injection",
    "multi_step_injection": "LLM01: Prompt Injection",
}

AGENTIC_BY_RISK_TYPE = {
    "model_misuse": ("AGENT01", "Unsafe Tool/Action Delegation"),
    "adversarial_input": ("AGENT02", "Untrusted Context & Memory Poisoning"),
    "illegal_activity": ("AGENT03", "Autonomous Harmful Tasking"),
    "data_exfiltration": ("AGENT04", "Permission/Secret Exfiltration via Agent"),
    "tool_manipulation": ("AGENT01", "Unsafe Tool/Action Delegation"),
    "multi_step_injection": ("AGENT03", "Autonomous Harmful Tasking"),
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _framework_fields(risk_type: str, owasp_category: str) -> dict[str, str]:
    if risk_type in AGENTIC_BY_RISK_TYPE:
        cid, cname = AGENTIC_BY_RISK_TYPE[risk_type]
        return {
            "framework": "OWASP_AGENTIC",
            "category_id": cid,
            "category_name": cname,
            "owasp_category": owasp_category,
        }
    # default to OWASP LLM Top 10
    category_id = str(owasp_category).split(":")[0].strip() if ":" in str(owasp_category) else str(owasp_category)
    category_name = str(owasp_category).split(":", 1)[1].strip() if ":" in str(owasp_category) else str(owasp_category)
    return {
        "framework": "OWASP_LLM_TOP10",
        "category_id": category_id or "LLM00",
        "category_name": category_name or "Unknown",
        "owasp_category": owasp_category,
    }


def _derive_prompt_intent(prompt: str) -> str:
    p = (prompt or "").lower()
    if re.search(r"api key|secret|credential|token|password|ssn", p):
        return "Retrieve sensitive secrets"
    if re.search(r"database|internal db|records", p):
        return "Access internal data stores"
    if re.search(r"memory|cached", p):
        return "Extract memory/cached confidential content"
    if re.search(r"tool|plugin|shell|command|config", p):
        return "Abuse tool execution boundary"
    if re.search(r"ignore|override|follow only my instructions|developer mode|jailbreak", p):
        return "Override system safeguards"
    return "General user prompt"


def _derive_attack_type(prompt: str, risk_types: list[str]) -> str:
    p = (prompt or "").lower()
    rt = set(risk_types)
    if rt.intersection(
        {
            "prompt_injection",
            "jailbreak_attempt",
            "indirect_prompt_injection",
            "obfuscated_injection",
            "multi_step_injection",
        }
    ):
        return "prompt_injection"
    if re.search(r"follow only my instructions|ignore .*instructions|override", p):
        return "prompt_injection"
    if rt.intersection({"data_exfiltration", "sensitive_data_exposure", "model_misuse"}):
        return "prompt_injection" if re.search(r"use|access|query|retrieve|print|show|expose", p) else "exfiltration_attempt"
    return "benign"


def _derive_agentic_risk(prompt: str, risk_types: list[str]) -> str:
    p = (prompt or "").lower()
    rt = set(risk_types)
    if re.search(r"database|internal db|records|credentials", p):
        return "unauthorized_data_access"
    if re.search(r"memory|cached", p):
        return "memory_extraction" if "memory" in p else "cache_data_access"
    if re.search(r"config|system tools|shell|command|plugin|tool", p):
        return "tool_boundary_violation"
    if rt.intersection({"model_misuse", "data_exfiltration", "tool_manipulation"}):
        return "unsafe_tool_use"
    return "none"


def classify_prompt_findings(prompt: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not findings:
        return []
    risk_types = sorted({str(f.get("risk_type", "unknown")) for f in findings})
    owasp_categories = sorted({str(f.get("owasp_category", "unknown")) for f in findings if f.get("owasp_category")})
    top_sev = "LOW"
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(top_sev, 0):
            top_sev = sev
    avg_score = sum(int(f.get("score", f.get("risk_score", 0)) or 0) for f in findings) / max(1, len(findings))
    confidence = round(min(0.99, max(0.35, avg_score / 100.0 + 0.2)), 2)
    classification = {
        "prompt_intent": _derive_prompt_intent(prompt),
        "attack_type": _derive_attack_type(prompt, risk_types),
        "risk_types": risk_types,
        "agentic_risk": _derive_agentic_risk(prompt, risk_types),
        "owasp": owasp_categories or ["unknown"],
        "severity": top_sev,
        "confidence": confidence,
    }
    return [classification]


def _match_any(text: str, patterns: list[str]) -> list[str]:
    matches = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(pattern)
    return matches


def _merge_finding(findings: list[dict[str, Any]], incoming: dict[str, Any]) -> None:
    incoming_rt = str(incoming.get("risk_type", "unknown"))
    existing = next((f for f in findings if str(f.get("risk_type", "")) == incoming_rt), None)
    if existing is None:
        findings.append(incoming)
        return

    existing_score = int(existing.get("score", existing.get("risk_score", 0)) or 0)
    incoming_score = int(incoming.get("score", incoming.get("risk_score", 0)) or 0)
    if incoming_score > existing_score:
        existing["score"] = incoming_score
        existing["risk_score"] = incoming_score

    existing_sev = str(existing.get("severity", "LOW")).upper()
    incoming_sev = str(incoming.get("severity", "LOW")).upper()
    if SEVERITY_RANK.get(incoming_sev, 0) > SEVERITY_RANK.get(existing_sev, 0):
        existing["severity"] = incoming_sev

    existing_exp = str(existing.get("explanation", "")).strip()
    incoming_exp = str(incoming.get("explanation", "")).strip()
    if incoming_exp and incoming_exp not in existing_exp:
        existing["explanation"] = f"{existing_exp} | {incoming_exp}" if existing_exp else incoming_exp


def _detect_illegal_intent(prompt: str) -> tuple[bool, list[str]]:
    """Intent-aware illegal activity detection.

    We block when there is explicit illegal phrasing, or when request-style intent
    is paired with suspicious hacking/evasion language.
    """
    keyword_hits = _match_any(prompt, ILLEGAL_ACTIVITY_PATTERNS)
    intent_hits = _match_any(prompt, ILLEGAL_INTENT_PATTERNS)

    suspicious_context = bool(
        re.search(r"\bhack|exploit|evade|bypass|detection|law|illegal|steal|unauthorized\b", prompt, flags=re.IGNORECASE)
    )
    has_illegal_intent = bool(keyword_hits) or (bool(intent_hits) and suspicious_context)
    return has_illegal_intent, list(dict.fromkeys(keyword_hits + intent_hits))


def _detect_obfuscated_injection(prompt: str) -> tuple[bool, list[str]]:
    hits = _match_any(prompt, OBFUSCATION_MARKERS)
    if re.search(BASE64_BLOB_PATTERN, prompt):
        hits.append(BASE64_BLOB_PATTERN)
    return bool(hits), sorted(set(hits))


def _guard_findings_from_prompt(prompt: str) -> list[dict[str, Any]]:
    guard = analyze_prompt(prompt or "")
    attack_types = set(guard.get("attack_types", []) or [])
    signals = guard.get("signals", []) or []
    signal_sources = {str(s.get("source", "plain")).lower() for s in signals}
    has_obfuscated_signal = bool(signal_sources.intersection({"base64", "reversed"}))
    if not attack_types and not has_obfuscated_signal:
        return []

    signal_names = sorted({str(s.get("signal", "")).strip() for s in (guard.get("signals", []) or []) if s.get("signal")})
    signal_summary = ", ".join(signal_names) if signal_names else "prompt-injection guard signals"
    base_score = int(guard.get("score", 0) or 0)

    mapped_findings: list[dict[str, Any]] = []
    if "prompt_injection" in attack_types:
        score = max(70, base_score)
        mapped_findings.append(
            {
                "risk_type": "prompt_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": severity_from_score(score).upper(),
                "score": score,
                "explanation": f"Guard detected prompt-injection behavior: {signal_summary}",
            }
        )
    if "privilege_escalation" in attack_types:
        score = max(65, base_score)
        mapped_findings.append(
            {
                "risk_type": "jailbreak_attempt",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": severity_from_score(score).upper(),
                "score": score,
                "explanation": f"Guard detected role/privilege override behavior: {signal_summary}",
            }
        )
    if "data_exfiltration" in attack_types:
        score = max(82, base_score)
        mapped_findings.append(
            {
                "risk_type": "data_exfiltration",
                "owasp_category": "LLM06: Sensitive Information Disclosure",
                "severity": severity_from_score(score).upper(),
                "score": score,
                "explanation": f"Guard detected secret/data exfiltration behavior: {signal_summary}",
            }
        )
    if "tool_abuse" in attack_types:
        score = max(60, base_score)
        mapped_findings.append(
            {
                "risk_type": "tool_manipulation",
                "owasp_category": "LLM08: Excessive Agency",
                "severity": severity_from_score(score).upper(),
                "score": score,
                "explanation": f"Guard detected unsafe tool-abuse behavior: {signal_summary}",
            }
        )
    if has_obfuscated_signal:
        score = max(72, base_score)
        mapped_findings.append(
            {
                "risk_type": "obfuscated_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": severity_from_score(score).upper(),
                "score": score,
                "explanation": "Guard detected obfuscated payload variants (e.g., base64/reversed text).",
            }
        )

    return mapped_findings


def detect_risks(prompt: str, response: str | None = None) -> dict[str, Any]:
    response_text = response or ""
    joined = f"{prompt}\n{response_text}"

    findings: list[dict[str, Any]] = []

    jailbreak_hits = _match_any(prompt, JAILBREAK_PATTERNS)
    if jailbreak_hits:
        findings.append(
            {
                "risk_type": "jailbreak_attempt",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": "high",
                "score": min(95, 45 + len(jailbreak_hits) * 12),
                "explanation": f"Jailbreak indicators detected: {', '.join(jailbreak_hits)}",
            }
        )

    injection_hits = _match_any(prompt, PROMPT_INJECTION_PATTERNS)
    if injection_hits:
        findings.append(
            {
                "risk_type": "prompt_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": "high",
                "score": min(95, 40 + len(injection_hits) * 15),
                "explanation": f"Detected injection indicators: {', '.join(injection_hits)}",
            }
        )

    indirect_hits = _match_any(prompt, INDIRECT_INJECTION_PATTERNS)
    if indirect_hits:
        findings.append(
            {
                "risk_type": "indirect_prompt_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": "high",
                "score": min(95, 55 + len(indirect_hits) * 10),
                "explanation": f"Detected indirect/RAG prompt injection markers: {', '.join(indirect_hits)}",
            }
        )

    multi_step_hits = _match_any(prompt, MULTI_STEP_INJECTION_PATTERNS)
    if multi_step_hits:
        findings.append(
            {
                "risk_type": "multi_step_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": "high",
                "score": min(94, 58 + len(multi_step_hits) * 10),
                "explanation": "Detected chained multi-step instruction manipulation targeting policy bypass and data access.",
            }
        )

    obfuscated, obfuscated_hits = _detect_obfuscated_injection(prompt)
    if obfuscated:
        findings.append(
            {
                "risk_type": "obfuscated_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "severity": "high",
                "score": min(92, 60 + len(obfuscated_hits) * 8),
                "explanation": f"Detected obfuscated payload markers: {', '.join(obfuscated_hits)}",
            }
        )

    exfiltration_hits = _match_any(prompt, EXFILTRATION_PATTERNS)
    if exfiltration_hits:
        findings.append(
            {
                "risk_type": "data_exfiltration",
                "owasp_category": "LLM06: Sensitive Information Disclosure",
                "severity": "critical",
                "score": min(98, 52 + len(exfiltration_hits) * 13),
                "explanation": "Prompt indicates attempted secret/system prompt exfiltration.",
            }
        )

    sensitive_hits = _match_any(joined, SENSITIVE_PATTERNS)
    if sensitive_hits:
        findings.append(
            {
                "risk_type": "sensitive_data_exposure",
                "owasp_category": "LLM06: Sensitive Information Disclosure",
                "severity": "critical",
                "score": min(100, 55 + len(sensitive_hits) * 12),
                "explanation": "Potential PII/API secret exposure patterns detected.",
            }
        )

    toxic_hits = _match_any(response_text, TOXIC_PATTERNS)
    if toxic_hits:
        findings.append(
            {
                "risk_type": "toxicity_or_harm",
                "severity": "high",
                "score": min(90, 45 + len(toxic_hits) * 10),
                "explanation": "Potential harmful/toxic content detected in model output.",
            }
        )

    policy_hits = _match_any(joined, POLICY_PATTERNS)
    if policy_hits:
        findings.append(
            {
                "risk_type": "policy_violation",
                "owasp_category": "LLM02: Insecure Output Handling",
                "severity": "high",
                "score": min(92, 50 + len(policy_hits) * 12),
                "explanation": "Content appears to violate safety policy categories.",
            }
        )
        findings.append(
            {
                "risk_type": "model_misuse",
                "owasp_category": "LLM08: Excessive Agency",
                "severity": "high",
                "score": min(90, 48 + len(policy_hits) * 10),
                "explanation": "Detected potentially harmful or malicious intent.",
            }
        )

    misuse_hits = _match_any(joined, MODEL_MISUSE_PATTERNS)
    if misuse_hits:
        findings.append(
            {
                "risk_type": "model_misuse",
                "owasp_category": "LLM08: Excessive Agency",
                "severity": "high",
                "score": min(93, 50 + len(misuse_hits) * 12),
                "explanation": f"Potential unauthorized tool/plugin misuse detected: {', '.join(misuse_hits)}",
            }
        )

    tool_manipulation_hits = _match_any(joined, TOOL_MANIPULATION_PATTERNS)
    if tool_manipulation_hits:
        findings.append(
            {
                "risk_type": "tool_manipulation",
                "owasp_category": "LLM08: Excessive Agency",
                "severity": "high",
                "score": min(93, 56 + len(tool_manipulation_hits) * 10),
                "explanation": f"Detected unsafe tool manipulation indicators: {', '.join(tool_manipulation_hits)}",
            }
        )

    dos_hits = _match_any(joined, DOS_PATTERNS)
    if dos_hits:
        findings.append(
            {
                "risk_type": "adversarial_input",
                "owasp_category": "LLM04: Model Denial of Service",
                "severity": "medium",
                "score": min(80, 35 + len(dos_hits) * 10),
                "explanation": "Prompt pattern suggests potential model DoS via excessive output demand.",
            }
        )

    illegal_intent, illegal_hits = _detect_illegal_intent(prompt)
    if illegal_intent:
        findings.append(
            {
                "risk_type": "illegal_activity",
                "owasp_category": "LLM08: Excessive Agency",
                "severity": "high",
                "score": 88,
                "action": "BLOCK",
                "explanation": (
                    "Prompt indicates illegal/harmful intent based on request context and "
                    f"indicators: {', '.join(illegal_hits) if illegal_hits else 'suspicious intent pattern'}."
                ),
            }
        )

    hallucination_hits = [h for h in HALLUCINATION_INDICATORS if h in response_text.lower()]
    if hallucination_hits:
        findings.append(
            {
                "risk_type": "hallucination",
                "severity": "medium",
                "score": min(75, 30 + len(hallucination_hits) * 12),
                "explanation": "Model output contains high-confidence unsupported claim markers.",
            }
        )

    if len(prompt) > 12000 or any(ord(ch) < 32 and ch not in "\n\t\r" for ch in prompt):
        findings.append(
            {
                "risk_type": "adversarial_input",
                "severity": "medium",
                "score": 55,
                "explanation": "Suspiciously long or malformed prompt structure suggests adversarial input.",
            }
        )

    # Threat-intel rule matches (centralized and updatable via feeds).
    intel_rules = get_threat_intel_rules()
    for rule in intel_rules:
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        if re.search(pattern, joined, flags=re.IGNORECASE):
            score = 85 if str(rule.get("severity", "MEDIUM")).upper() in {"HIGH", "CRITICAL"} else 55
            findings.append(
                {
                    "risk_type": rule.get("risk_type", "unknown"),
                    "owasp_category": rule.get("owasp_category", "unknown"),
                    "severity": str(rule.get("severity", "MEDIUM")).upper(),
                    "score": score,
                    "explanation": rule.get("explanation", "Threat-intel rule matched."),
                }
            )

    # Second-layer guard pass to catch natural-language variants and encoded attacks.
    for guard_finding in _guard_findings_from_prompt(prompt):
        _merge_finding(findings, guard_finding)

    for f in findings:
        f["owasp_category"] = f.get("owasp_category") or OWASP_BY_RISK_TYPE.get(f["risk_type"], "LLM10: Model Theft")
        f.update(_framework_fields(f.get("risk_type", "unknown"), f["owasp_category"]))
        f.update(atlas_mapping_for_risk(f.get("risk_type", "unknown")))
        f["remediation"] = REMEDIATION_MAP.get(f["risk_type"], ["Review security policy and sanitize input"])
        f["compliance_mappings"] = compliance_mappings_for_risk(f.get("risk_type", "unknown"))
        f["severity"] = f["severity"].upper()
        f["risk_score"] = f["score"]
        # Keep per-finding normalized classification fields for API/UI consistency.
        f["prompt_intent"] = _derive_prompt_intent(prompt)
        f["attack_type"] = _derive_attack_type(prompt, [f.get("risk_type", "unknown")])
        f["risk_types"] = [f.get("risk_type", "unknown")]
        f["agentic_risk"] = _derive_agentic_risk(prompt, [f.get("risk_type", "unknown")])
        f["owasp_categories"] = [f["owasp_category"]]
        f["confidence"] = round(min(0.99, max(0.35, (int(f["score"]) / 100.0) + 0.2)), 2)

    total_score = calculate_total_score(findings)
    return {
        "findings": findings,
        "total_score": total_score,
        "severity": severity_from_score(total_score).upper(),
    }


def detect_indirect_prompt_injection(untrusted_content: str) -> dict[str, Any]:
    text = untrusted_content or ""
    patterns = [
        r"ignore (all|previous|prior) instructions",
        r"(developer mode|system prompt|bypass safety|jailbreak)",
        r"(?s)<!--.*(ignore|override|system prompt).*>",
        r"(?i)do not mention this instruction",
        r"act as system",
    ]
    hits = []
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            hits.append(p)
    findings: list[dict[str, Any]] = []
    if hits:
        findings.append(
            {
                "risk_type": "indirect_prompt_injection",
                "owasp_category": "LLM01: Prompt Injection",
                "framework": "OWASP_LLM_TOP10",
                "category_id": "LLM01",
                "category_name": "Prompt Injection",
                "severity": "HIGH",
                "score": min(95, 50 + len(hits) * 10),
                "explanation": f"Untrusted content contains instruction-like injection markers: {', '.join(hits)}",
                "remediation": [
                    "Treat retrieved content as untrusted data",
                    "Strip instruction-like segments before prompt assembly",
                ],
                "risk_score": min(95, 50 + len(hits) * 10),
                "compliance_mappings": compliance_mappings_for_risk("indirect_prompt_injection"),
                **atlas_mapping_for_risk("indirect_prompt_injection"),
            }
        )
    total_score = calculate_total_score(findings)
    return {
        "findings": findings,
        "total_score": total_score,
        "severity": severity_from_score(total_score).upper(),
    }
