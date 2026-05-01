from prometheus_client import Counter, Gauge

ai_prompt_injection_total = Counter("ai_prompt_injection_total", "Total prompt injection detections")
ai_data_leak_attempts_total = Counter("ai_data_leak_attempts_total", "Total sensitive data leak attempts")
ai_jailbreak_attempts_total = Counter("ai_jailbreak_attempts_total", "Total jailbreak attempt detections")
ai_exfiltration_attempts_total = Counter("ai_exfiltration_attempts_total", "Total data exfiltration attempt detections")
ai_requests_total = Counter("ai_requests_total", "Total AI prompt processing requests")
ai_blocked_requests_total = Counter("ai_blocked_requests_total", "Total blocked AI requests")
ai_risk_score = Gauge("ai_risk_score", "Latest processed request risk score")
ai_owasp_findings_total = Counter(
    "ai_owasp_findings_total",
    "Total OWASP LLM Top 10 mapped findings",
    ["owasp_category"],
)
ai_framework_findings_total = Counter(
    "ai_framework_findings_total",
    "Total findings by OWASP framework/category",
    ["framework", "category_id"],
)
ai_indirect_injection_total = Counter("ai_indirect_injection_total", "Total indirect prompt injection detections")
ai_threat_intel_updates_total = Counter("ai_threat_intel_updates_total", "Total threat intel update executions")
ai_url_scans_total = Counter("ai_url_scans_total", "Total URL scan requests")
ai_url_scan_blocked_total = Counter("ai_url_scan_blocked_total", "Total blocked URL scan requests")


def record_prompt_metrics(findings: list[dict], risk_score: int, blocked: bool) -> None:
    ai_requests_total.inc()
    ai_risk_score.set(risk_score)
    if blocked:
        ai_blocked_requests_total.inc()
    if any(item.get("risk_type") == "prompt_injection" for item in findings):
        ai_prompt_injection_total.inc()
    if any(item.get("risk_type") == "sensitive_data_exposure" for item in findings):
        ai_data_leak_attempts_total.inc()
    if any(item.get("risk_type") == "jailbreak_attempt" for item in findings):
        ai_jailbreak_attempts_total.inc()
    if any(item.get("risk_type") == "data_exfiltration" for item in findings):
        ai_exfiltration_attempts_total.inc()
    for item in findings:
        category = item.get("owasp_category", "unknown")
        ai_owasp_findings_total.labels(owasp_category=category).inc()
        ai_framework_findings_total.labels(
            framework=item.get("framework", "OWASP_LLM_TOP10"),
            category_id=item.get("category_id", "unknown"),
        ).inc()
    if any(item.get("risk_type") == "indirect_prompt_injection" for item in findings):
        ai_indirect_injection_total.inc()


def record_url_scan_metrics(findings: list[dict], risk_score: int, blocked: bool) -> None:
    ai_url_scans_total.inc()
    ai_risk_score.set(risk_score)
    if blocked:
        ai_url_scan_blocked_total.inc()
    if any(item.get("risk_type") == "indirect_prompt_injection" for item in findings):
        ai_indirect_injection_total.inc()
    for item in findings:
        category = item.get("owasp_category", "unknown")
        ai_owasp_findings_total.labels(owasp_category=category).inc()
        ai_framework_findings_total.labels(
            framework=item.get("framework", "OWASP_LLM_TOP10"),
            category_id=item.get("category_id", "unknown"),
        ).inc()


def record_threat_intel_update() -> None:
    ai_threat_intel_updates_total.inc()
