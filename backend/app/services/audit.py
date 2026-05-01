import hashlib
import json
from sqlalchemy.orm import Session

from app.models import AuditLog


def _hash_event(payload: dict, prev_hash: str | None) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    combined = f"{prev_hash or ''}|{raw}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def write_audit_event(
    db: Session,
    event_type: str,
    details: dict,
    actor_user_id: int | None = None,
    scan_id: int | None = None,
) -> AuditLog:
    prev = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = prev.event_hash if prev else None
    payload = {
        "event_type": event_type,
        "actor_user_id": actor_user_id,
        "scan_id": scan_id,
        "details": details,
    }
    event_hash = _hash_event(payload, prev_hash)

    row = AuditLog(
        event_type=event_type,
        actor_user_id=actor_user_id,
        scan_id=scan_id,
        details=details,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(row)
    db.flush()
    return row
