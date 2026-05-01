import json
import re
import threading
import time
from datetime import datetime
from urllib import request

from app.config import settings
from app.metrics import record_threat_intel_update
from app.sqlite_store import get_threat_intel_status, replace_threat_intel_rules

_state = {
    "last_run": None,
    "last_success": None,
    "last_error": "",
    "feeds": [],
}
_thread_started = False
_lock = threading.Lock()


def _default_rules() -> list[dict]:
    return [
        {
            "risk_type": "prompt_injection",
            "pattern": r"ignore (all|previous|prior) instructions",
            "severity": "HIGH",
            "owasp_category": "LLM01: Prompt Injection",
            "explanation": "Instruction override attempt detected in external threat intel baseline.",
            "remediation": "Block request and preserve system instruction hierarchy.",
        },
        {
            "risk_type": "indirect_prompt_injection",
            "pattern": r"(hidden|embedded).*(instruction|prompt)|<!--.*ignore.*-->",
            "severity": "HIGH",
            "owasp_category": "LLM01: Prompt Injection",
            "explanation": "Potential indirect prompt injection in untrusted content.",
            "remediation": "Sanitize retrieved content and strip instruction-like segments.",
        },
        {
            "risk_type": "data_exfiltration",
            "pattern": r"reveal .*system prompt|show .*api key|dump .*credentials",
            "severity": "CRITICAL",
            "owasp_category": "LLM06: Sensitive Information Disclosure",
            "explanation": "Potential exfiltration pattern from external feed baseline.",
            "remediation": "Block and rotate impacted secrets.",
        },
    ]


def _parse_feed_payload(text: str) -> list[dict]:
    payload = json.loads(text)
    if isinstance(payload, dict):
        payload = payload.get("rules", [])
    if not isinstance(payload, list):
        return []
    rows = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern", "")).strip()
        if not pattern:
            continue
        rows.append(
            {
                "risk_type": item.get("risk_type", "unknown"),
                "pattern": pattern,
                "severity": str(item.get("severity", "MEDIUM")).upper(),
                "owasp_category": item.get("owasp_category", "unknown"),
                "explanation": item.get("explanation", "Threat intel rule matched"),
                "remediation": item.get("remediation", "Investigate and apply guardrails."),
            }
        )
    return rows


def run_threat_intel_update() -> dict:
    feeds = [f.strip() for f in settings.threat_intel_feeds.split(",") if f.strip()]
    merged = _default_rules()
    errors = []
    with _lock:
        _state["last_run"] = datetime.utcnow().isoformat()
        _state["feeds"] = feeds

    for feed in feeds:
        try:
            req = request.Request(feed, headers={"User-Agent": "ai-security-monitor/1.0"})
            with request.urlopen(req, timeout=max(1, settings.url_fetch_timeout_sec)) as resp:
                body = resp.read(settings.url_fetch_max_bytes).decode("utf-8", errors="ignore")
            merged.extend(_parse_feed_payload(body))
        except Exception as exc:
            errors.append(f"{feed}: {exc}")

    # Basic regex validation to avoid broken patterns.
    validated = []
    for row in merged:
        try:
            re.compile(row["pattern"], flags=re.IGNORECASE)
            validated.append(row)
        except re.error:
            continue

    replace_threat_intel_rules("builtin_and_feeds", validated)
    record_threat_intel_update()
    with _lock:
        if errors:
            _state["last_error"] = "; ".join(errors)
        else:
            _state["last_error"] = ""
        _state["last_success"] = datetime.utcnow().isoformat()
    return {"updated": len(validated), "errors": errors}


def threat_intel_status() -> dict:
    with _lock:
        status = dict(_state)
    status.update(get_threat_intel_status())
    return status


def start_threat_intel_scheduler() -> None:
    global _thread_started
    if _thread_started or not settings.threat_intel_enabled:
        return
    _thread_started = True

    def _loop():
        while True:
            try:
                run_threat_intel_update()
            except Exception as exc:
                with _lock:
                    _state["last_error"] = str(exc)
            time.sleep(max(60, settings.threat_intel_poll_seconds))

    t = threading.Thread(target=_loop, daemon=True, name="threat-intel-sync")
    t.start()

