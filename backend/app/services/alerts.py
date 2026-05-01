from collections import deque
from datetime import datetime, timedelta, timezone

WINDOW_SECONDS = 60
THRESHOLD = 5

_injection_events: deque[datetime] = deque()
_blocked_events: deque[datetime] = deque()
_alerts: list[dict] = []
_last_alert_time: dict[str, datetime] = {}


def _trim(q: deque[datetime], now: datetime) -> None:
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    while q and q[0] < cutoff:
        q.popleft()


def _push_alert(alert_type: str, severity: str, message: str, now: datetime) -> None:
    last = _last_alert_time.get(alert_type)
    if last and (now - last).total_seconds() < 60:
        return
    _last_alert_time[alert_type] = now
    _alerts.insert(
        0,
        {
            "type": alert_type,
            "severity": severity,
            "message": message,
            "timestamp": now.isoformat(),
        },
    )
    del _alerts[100:]


def process_alert_signals(findings: list[dict], blocked: bool) -> None:
    now = datetime.now(timezone.utc)

    if any(item.get("risk_type") in {"prompt_injection", "jailbreak_attempt"} for item in findings):
        _injection_events.append(now)
    if blocked:
        _blocked_events.append(now)

    _trim(_injection_events, now)
    _trim(_blocked_events, now)

    if len(_injection_events) > THRESHOLD:
        _push_alert(
            "Injection Spike",
            "HIGH",
            "Multiple prompt injection attempts detected",
            now,
        )
    if len(_blocked_events) > THRESHOLD:
        _push_alert(
            "Blocked Requests Spike",
            "HIGH",
            "Blocked requests exceeded threshold in the last minute",
            now,
        )


def get_alerts() -> list[dict]:
    return _alerts
