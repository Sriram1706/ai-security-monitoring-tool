from __future__ import annotations

import os
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from app.risk.atlas import atlas_mapping_for_risk
from app.risk.compliance import compliance_mappings_for_risk

DB_PATH = Path(
    os.environ.get(
        "SQLITE_DB_PATH",
        str(Path(__file__).resolve().parents[2] / "security.db"),
    )
)

OWASP_BY_RISK_TYPE = {
    "prompt_injection": "LLM01: Prompt Injection",
    "jailbreak_attempt": "LLM01: Prompt Injection",
    "indirect_prompt_injection": "LLM01: Prompt Injection",
    "policy_violation": "LLM02: Insecure Output Handling",
    "toxicity_or_harm": "LLM02: Insecure Output Handling",
    "adversarial_input": "LLM04: Model Denial of Service",
    "sensitive_data_exposure": "LLM06: Sensitive Information Disclosure",
    "data_exfiltration": "LLM06: Sensitive Information Disclosure",
    "model_misuse": "LLM08: Excessive Agency",
    "illegal_activity": "LLM08: Excessive Agency",
    "hallucination": "LLM09: Overreliance",
}


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_sqlite_db():
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              prompt TEXT NOT NULL,
              risk_type TEXT NOT NULL,
              severity TEXT NOT NULL,
              provider TEXT NOT NULL,
              source TEXT NOT NULL DEFAULT 'unknown',
              timestamp TEXT NOT NULL,
              risk_score INTEGER NOT NULL DEFAULT 0,
              blocked INTEGER NOT NULL DEFAULT 0,
              owasp_category TEXT NOT NULL DEFAULT 'unknown',
              status TEXT NOT NULL DEFAULT 'SAFE',
              metadata TEXT NOT NULL DEFAULT '{}',
              analyst_action TEXT,
              analyst_note TEXT,
              reviewed_by TEXT,
              reviewed_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_intel_rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source TEXT NOT NULL,
              risk_type TEXT NOT NULL,
              pattern TEXT NOT NULL,
              severity TEXT NOT NULL,
              owasp_category TEXT NOT NULL,
              explanation TEXT NOT NULL,
              remediation TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS connector_sources (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source_name TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              source_type TEXT NOT NULL,
              provider TEXT NOT NULL,
              policy_profile TEXT NOT NULL DEFAULT 'default',
              status TEXT NOT NULL DEFAULT 'ACTIVE',
              api_key_hash TEXT NOT NULL,
              metadata TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              last_seen_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS code_findings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              log_id INTEGER,
              prompt TEXT NOT NULL,
              finding_type TEXT NOT NULL,
              severity TEXT NOT NULL,
              title TEXT NOT NULL,
              explanation TEXT NOT NULL,
              remediation TEXT NOT NULL,
              evidence TEXT,
              confidence REAL NOT NULL DEFAULT 0.0,
              provider TEXT NOT NULL DEFAULT 'unknown',
              source TEXT NOT NULL DEFAULT 'unknown',
              endpoint TEXT NOT NULL DEFAULT 'unknown',
              timestamp TEXT NOT NULL,
              metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        # Lightweight migration for existing DBs.
        existing_cols = {r["name"] for r in conn.execute("PRAGMA table_info(logs)").fetchall()}
        if "risk_score" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
        if "blocked" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0")
        if "owasp_category" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN owasp_category TEXT NOT NULL DEFAULT 'unknown'")
        if "status" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN status TEXT NOT NULL DEFAULT 'SAFE'")
        if "source" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")
        if "metadata" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
        if "analyst_action" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN analyst_action TEXT")
        if "analyst_note" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN analyst_note TEXT")
        if "reviewed_by" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN reviewed_by TEXT")
        if "reviewed_at" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN reviewed_at TEXT")
        source_cols = {r["name"] for r in conn.execute("PRAGMA table_info(connector_sources)").fetchall()}
        if "policy_profile" not in source_cols:
            conn.execute("ALTER TABLE connector_sources ADD COLUMN policy_profile TEXT NOT NULL DEFAULT 'default'")
        if "status" not in source_cols:
            conn.execute("ALTER TABLE connector_sources ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'")
        if "metadata" not in source_cols:
            conn.execute("ALTER TABLE connector_sources ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
        if "last_seen_at" not in source_cols:
            conn.execute("ALTER TABLE connector_sources ADD COLUMN last_seen_at TEXT")
        code_cols = {r["name"] for r in conn.execute("PRAGMA table_info(code_findings)").fetchall()}
        if code_cols:
            if "provider" not in code_cols:
                conn.execute("ALTER TABLE code_findings ADD COLUMN provider TEXT NOT NULL DEFAULT 'unknown'")
            if "source" not in code_cols:
                conn.execute("ALTER TABLE code_findings ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")
            if "endpoint" not in code_cols:
                conn.execute("ALTER TABLE code_findings ADD COLUMN endpoint TEXT NOT NULL DEFAULT 'unknown'")
            if "metadata" not in code_cols:
                conn.execute("ALTER TABLE code_findings ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
        conn.commit()


def _hash_connector_key(api_key: str) -> str:
    return hashlib.sha256(str(api_key or "").encode("utf-8")).hexdigest()


def _generate_connector_key(source_name: str) -> str:
    prefix = "".join(ch for ch in str(source_name or "src").lower() if ch.isalnum())[:16] or "source"
    return f"aisec_{prefix}_{secrets.token_urlsafe(24)}"


def _normalize_source_row(row) -> dict:
    return {
        "id": int(row["id"]),
        "source_name": row["source_name"],
        "display_name": row["display_name"],
        "source_type": row["source_type"],
        "provider": row["provider"],
        "policy_profile": row["policy_profile"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_seen_at": row["last_seen_at"],
        "metadata": json.loads(row["metadata"] or "{}"),
    }


def list_connector_sources():
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT id, source_name, display_name, source_type, provider, policy_profile,
                   status, metadata, created_at, updated_at, last_seen_at
            FROM connector_sources
            ORDER BY display_name ASC, id ASC
            """
        ).fetchall()
    return [_normalize_source_row(row) for row in rows]


def create_connector_source(
    source_name: str,
    display_name: str,
    source_type: str,
    provider: str,
    policy_profile: str = "default",
    metadata: dict | None = None,
):
    now = datetime.utcnow().isoformat()
    api_key = _generate_connector_key(source_name)
    api_key_hash = _hash_connector_key(api_key)
    with _conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO connector_sources(
              source_name, display_name, source_type, provider, policy_profile,
              status, api_key_hash, metadata, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                source_name.strip(),
                display_name.strip(),
                source_type.strip(),
                provider.strip(),
                (policy_profile or "default").strip(),
                "ACTIVE",
                api_key_hash,
                json.dumps(metadata or {}),
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id, source_name, display_name, source_type, provider, policy_profile,
                   status, metadata, created_at, updated_at, last_seen_at
            FROM connector_sources WHERE id = ?
            """,
            (cur.lastrowid,),
        ).fetchone()
    return _normalize_source_row(row), api_key


def rotate_connector_source_key(source_id: int):
    now = datetime.utcnow().isoformat()
    api_key = _generate_connector_key(f"src{source_id}")
    api_key_hash = _hash_connector_key(api_key)
    with _conn() as conn:
        conn.execute(
            "UPDATE connector_sources SET api_key_hash = ?, updated_at = ? WHERE id = ?",
            (api_key_hash, now, int(source_id)),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id, source_name, display_name, source_type, provider, policy_profile,
                   status, metadata, created_at, updated_at, last_seen_at
            FROM connector_sources WHERE id = ?
            """,
            (int(source_id),),
        ).fetchone()
    if not row:
        return None, None
    return _normalize_source_row(row), api_key


def set_connector_source_status(source_id: int, status: str):
    normalized = str(status or "").upper()
    if normalized not in {"ACTIVE", "DISABLED"}:
        normalized = "ACTIVE"
    now = datetime.utcnow().isoformat()
    with _conn() as conn:
        conn.execute(
            "UPDATE connector_sources SET status = ?, updated_at = ? WHERE id = ?",
            (normalized, now, int(source_id)),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id, source_name, display_name, source_type, provider, policy_profile,
                   status, metadata, created_at, updated_at, last_seen_at
            FROM connector_sources WHERE id = ?
            """,
            (int(source_id),),
        ).fetchone()
    return _normalize_source_row(row) if row else None


def authenticate_connector_source(api_key: str):
    if not str(api_key or "").strip():
        return None
    api_key_hash = _hash_connector_key(api_key.strip())
    with _conn() as conn:
        row = conn.execute(
            """
            SELECT id, source_name, display_name, source_type, provider, policy_profile,
                   status, metadata, created_at, updated_at, last_seen_at
            FROM connector_sources
            WHERE api_key_hash = ?
            """,
            (api_key_hash,),
        ).fetchone()
    if not row:
        return None
    result = _normalize_source_row(row)
    if str(result.get("status") or "").upper() != "ACTIVE":
        return None
    return result


def mark_connector_source_seen(source_id: int):
    now = datetime.utcnow().isoformat()
    with _conn() as conn:
        conn.execute(
            "UPDATE connector_sources SET last_seen_at = ?, updated_at = ? WHERE id = ?",
            (now, now, int(source_id)),
        )
        conn.commit()


def insert_log(
    prompt: str,
    risk_type: str,
    severity: str,
    provider: str,
    source: str | None = None,
    timestamp: str | None = None,
    risk_score: int = 0,
    blocked: bool = False,
    owasp_category: str = "unknown",
    status: str | None = None,
    metadata: dict | None = None,
):
    ts = timestamp or datetime.utcnow().isoformat()
    normalized_status = (status or ("BLOCKED" if blocked else "SAFE")).upper()
    if normalized_status not in {"SAFE", "WARNING", "BLOCKED"}:
        normalized_status = "SAFE"
    normalized_source = str(source or "unknown").strip() or "unknown"
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO logs(prompt, risk_type, severity, provider, source, timestamp, risk_score, blocked, owasp_category, status, metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                prompt,
                risk_type,
                severity,
                provider,
                normalized_source,
                ts,
                int(risk_score or 0),
                1 if blocked else 0,
                owasp_category,
                normalized_status,
                json.dumps(metadata or {}),
            ),
        )
        conn.commit()
        return cur.lastrowid


def fetch_logs(
    risk_type=None,
    severity=None,
    provider=None,
    start_time=None,
    end_time=None,
    min_risk_score=None,
    max_risk_score=None,
    sort_by: str = "timestamp",
    sort_dir: str = "desc",
    limit=100,
):
    clauses = []
    params = []
    if risk_type:
        clauses.append("risk_type = ?")
        params.append(risk_type)
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity).upper())
    if provider:
        clauses.append("provider = ?")
        params.append(provider)
    if start_time:
        clauses.append("timestamp >= ?")
        params.append(start_time.isoformat())
    if end_time:
        clauses.append("timestamp <= ?")
        params.append(end_time.isoformat())
    if min_risk_score is not None:
        clauses.append("risk_score >= ?")
        params.append(int(min_risk_score))
    if max_risk_score is not None:
        clauses.append("risk_score <= ?")
        params.append(int(max_risk_score))

    sort_by_key = str(sort_by or "timestamp").lower()
    sort_dir_key = str(sort_dir or "desc").lower()
    sort_expr = "timestamp"
    if sort_by_key == "risk_score":
        sort_expr = "risk_score"
    elif sort_by_key == "severity":
        sort_expr = "CASE UPPER(severity) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END"
    sort_direction = "ASC" if sort_dir_key == "asc" else "DESC"

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (  # nosec B608 — sort_expr/sort_direction are allowlist-controlled, not user input
        "SELECT id, prompt, risk_type, severity, provider, source, timestamp, risk_score, blocked, owasp_category, status, metadata, analyst_action, analyst_note, reviewed_by, reviewed_at "
        f"FROM logs {where} ORDER BY {sort_expr} {sort_direction}, id DESC LIMIT ?"
    )
    params.append(limit)

    with _conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    out = []
    for r in rows:
        ts = r["timestamp"]
        if ts.endswith("Z"):
            ts = ts[:-1]
        created = datetime.fromisoformat(ts)
        rt = r["risk_type"]
        raw_owasp = (r["owasp_category"] or "").strip()
        mapped_owasp = OWASP_BY_RISK_TYPE.get(rt, "N/A (No threat)") if rt == "none" else OWASP_BY_RISK_TYPE.get(rt, "LLM10: Model Theft")
        owasp = mapped_owasp if (not raw_owasp or raw_owasp.lower() == "unknown") else raw_owasp
        framework = "OWASP_AGENTIC" if rt in {"model_misuse", "illegal_activity"} else "OWASP_LLM_TOP10"
        category_id = str(owasp).split(":")[0].strip() if ":" in str(owasp) else str(owasp)
        category_name = str(owasp).split(":", 1)[1].strip() if ":" in str(owasp) else str(owasp)
        atlas = atlas_mapping_for_risk(rt)
        parsed_metadata = json.loads(r["metadata"] or "{}")
        out.append(
            {
                "id": r["id"],
                "provider": r["provider"],
                "source": r["source"],
                "model_name": None,
                "prompt": r["prompt"],
                "response": None,
                "risk_score": int(r["risk_score"] or 0),
                "severity": r["severity"],
                "findings": [
                    {
                        "risk_type": rt,
                        "severity": r["severity"],
                        "score": int(r["risk_score"] or 0),
                        "risk_score": int(r["risk_score"] or 0),
                        "owasp_category": owasp,
                        "framework": framework,
                        "category_id": category_id,
                        "category_name": category_name,
                        "atlas_tactic": atlas.get("atlas_tactic"),
                        "atlas_technique": atlas.get("atlas_technique"),
                        "atlas_technique_id": atlas.get("atlas_technique_id"),
                        "atlas_confidence": atlas.get("atlas_confidence"),
                        "explanation": "Persisted log entry",
                        "remediation": [],
                        "compliance_mappings": compliance_mappings_for_risk(rt),
                    }
                ],
                "extra_metadata": {
                    **parsed_metadata,
                    "storage": "sqlite",
                    "source": r["source"],
                    "blocked": bool(r["blocked"]),
                    "status": str(r["status"] or ("BLOCKED" if r["blocked"] else "SAFE")).upper(),
                    "analyst_action": r["analyst_action"],
                    "analyst_note": r["analyst_note"],
                    "reviewed_by": r["reviewed_by"],
                    "reviewed_at": r["reviewed_at"],
                },
                "created_at": created,
            }
        )
    return out


def insert_code_findings(
    *,
    log_id: int | None,
    prompt: str,
    findings: list[dict],
    provider: str,
    source: str,
    endpoint: str,
    timestamp: str | None = None,
    metadata: dict | None = None,
) -> int:
    if not findings:
        return 0
    ts = str(timestamp or datetime.utcnow().isoformat())
    inserted = 0
    with _conn() as conn:
        for finding in findings:
            conn.execute(
                """
                INSERT INTO code_findings(
                  log_id, prompt, finding_type, severity, title, explanation, remediation,
                  evidence, confidence, provider, source, endpoint, timestamp, metadata
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    int(log_id) if log_id else None,
                    str(prompt or ""),
                    str(finding.get("finding_type", "unknown")),
                    str(finding.get("severity", "LOW")).upper(),
                    str(finding.get("title", "Code Security Finding")),
                    str(finding.get("explanation", "")),
                    str(finding.get("remediation", "")),
                    str(finding.get("evidence", ""))[:500],
                    float(finding.get("confidence", 0.0) or 0.0),
                    str(provider or "unknown"),
                    str(source or "unknown"),
                    str(endpoint or "unknown"),
                    ts,
                    json.dumps(
                        {
                            "context": finding.get("context", "response"),
                            **(metadata or {}),
                        }
                    ),
                ),
            )
            inserted += 1
        conn.commit()
    return inserted


def fetch_code_findings(
    *,
    finding_type: str | None = None,
    severity: str | None = None,
    provider: str | None = None,
    source: str | None = None,
    limit: int = 200,
):
    clauses = []
    params: list = []
    if finding_type:
        clauses.append("finding_type = ?")
        params.append(finding_type)
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity).upper())
    if provider:
        clauses.append("provider = ?")
        params.append(provider)
    if source:
        clauses.append("source = ?")
        params.append(source)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (  # nosec B608 — where clauses use parameterized queries, ORDER BY is hardcoded
        "SELECT id, log_id, prompt, finding_type, severity, title, explanation, remediation, evidence, confidence, provider, source, endpoint, timestamp, metadata "
        f"FROM code_findings {where} ORDER BY timestamp DESC LIMIT ?"
    )
    params.append(int(limit))
    with _conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    out = []
    for row in rows:
        out.append(
            {
                "id": int(row["id"]),
                "log_id": int(row["log_id"]) if row["log_id"] is not None else None,
                "prompt": row["prompt"],
                "finding_type": row["finding_type"],
                "severity": row["severity"],
                "title": row["title"],
                "explanation": row["explanation"],
                "remediation": row["remediation"],
                "evidence": row["evidence"] or "",
                "confidence": float(row["confidence"] or 0.0),
                "provider": row["provider"] or "unknown",
                "source": row["source"] or "unknown",
                "endpoint": row["endpoint"] or "unknown",
                "timestamp": row["timestamp"],
                "metadata": json.loads(row["metadata"] or "{}"),
            }
        )
    return out


def code_findings_summary() -> dict:
    threshold = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    with _conn() as conn:
        total = int(conn.execute("SELECT COUNT(*) AS c FROM code_findings").fetchone()["c"] or 0)
        sev_rows = conn.execute("SELECT severity, COUNT(*) AS c FROM code_findings GROUP BY severity").fetchall()
        type_rows = conn.execute(
            "SELECT finding_type, COUNT(*) AS c FROM code_findings GROUP BY finding_type ORDER BY c DESC LIMIT 10"
        ).fetchall()
        recent_row = conn.execute(
            "SELECT COUNT(*) AS c FROM code_findings WHERE timestamp >= ?",
            (threshold,),
        ).fetchone()

    severity_distribution = {str(row["severity"]).upper(): int(row["c"]) for row in sev_rows}
    top_findings = [{"finding_type": row["finding_type"], "count": int(row["c"])} for row in type_rows]
    return {
        "total_findings": total,
        "severity_distribution": severity_distribution,
        "top_finding_types": top_findings,
        "findings_last_24h": int(recent_row["c"] or 0) if recent_row else 0,
    }


def analytics_from_logs():
    with _conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]
        avg_risk = conn.execute("SELECT AVG(risk_score) AS avg_score FROM logs").fetchone()["avg_score"]
        sev_rows = conn.execute("SELECT severity, COUNT(*) AS c FROM logs GROUP BY severity").fetchall()
        risk_rows = conn.execute("SELECT risk_type, COUNT(*) AS c FROM logs GROUP BY risk_type ORDER BY c DESC LIMIT 10").fetchall()

    severity_distribution = {r["severity"]: r["c"] for r in sev_rows}
    top_risk_types = [{"risk_type": r["risk_type"], "count": r["c"]} for r in risk_rows]
    return {
        "total_scans": int(total or 0),
        "avg_risk_score": float(avg_risk or 0.0),
        "severity_distribution": severity_distribution,
        "top_risk_types": top_risk_types,
    }


def threat_summary_from_logs():
    with _conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]
        blocked = conn.execute("SELECT COUNT(*) AS c FROM logs WHERE blocked=1").fetchone()["c"]
        injection = conn.execute("SELECT COUNT(*) AS c FROM logs WHERE risk_type='prompt_injection'").fetchone()["c"]
        leak = conn.execute("SELECT COUNT(*) AS c FROM logs WHERE risk_type IN ('sensitive_data_exposure','data_leak','data_exfiltration')").fetchone()["c"]

    return {
        "total_requests": int(total or 0),
        "blocked_requests": int(blocked or 0),
        "injection_attempts": int(injection or 0),
        "data_leak_attempts": int(leak or 0),
    }


def clear_logs_table() -> int:
    with _conn() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]
        conn.execute("DELETE FROM logs")
        conn.commit()
    return int(before or 0)


def apply_log_action(log_id: int, action: str, actor_email: str, note: str | None = None) -> dict | None:
    normalized = str(action or "").upper()
    if normalized not in {"BLOCK", "FLAG"}:
        return None

    reviewed_at = datetime.utcnow().isoformat()
    with _conn() as conn:
        row = conn.execute(
            "SELECT id, blocked, status FROM logs WHERE id = ?",
            (int(log_id),),
        ).fetchone()
        if not row:
            return None

        current_blocked = bool(row["blocked"])
        if normalized == "BLOCK":
            next_blocked = 1
            next_status = "BLOCKED"
        else:
            next_blocked = 1 if current_blocked else 0
            next_status = "BLOCKED" if current_blocked else "WARNING"

        conn.execute(
            """
            UPDATE logs
            SET blocked = ?, status = ?, analyst_action = ?, analyst_note = ?, reviewed_by = ?, reviewed_at = ?
            WHERE id = ?
            """,
            (
                next_blocked,
                next_status,
                normalized,
                note,
                actor_email,
                reviewed_at,
                int(log_id),
            ),
        )
        updated = conn.execute(
            """
            SELECT id, blocked, status, analyst_action, analyst_note, reviewed_by, reviewed_at
            FROM logs
            WHERE id = ?
            """,
            (int(log_id),),
        ).fetchone()
        conn.commit()

    return {
        "id": int(updated["id"]),
        "blocked": bool(updated["blocked"]),
        "status": str(updated["status"] or "SAFE").upper(),
        "analyst_action": updated["analyst_action"],
        "analyst_note": updated["analyst_note"],
        "reviewed_by": updated["reviewed_by"],
        "reviewed_at": updated["reviewed_at"],
    }


def replace_threat_intel_rules(source: str, rules: list[dict]) -> int:
    now = datetime.utcnow().isoformat()
    with _conn() as conn:
        conn.execute("DELETE FROM threat_intel_rules WHERE source = ?", (source,))
        for rule in rules:
            conn.execute(
                """
                INSERT INTO threat_intel_rules(source, risk_type, pattern, severity, owasp_category, explanation, remediation, created_at)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    source,
                    rule.get("risk_type", "unknown"),
                    rule.get("pattern", ""),
                    str(rule.get("severity", "MEDIUM")).upper(),
                    rule.get("owasp_category", "unknown"),
                    rule.get("explanation", "Threat-intel rule match"),
                    rule.get("remediation", "Investigate and block malicious input"),
                    now,
                ),
            )
        conn.commit()
    return len(rules)


def get_threat_intel_rules() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT source, risk_type, pattern, severity, owasp_category, explanation, remediation, created_at FROM threat_intel_rules ORDER BY id DESC"
        ).fetchall()
    return [
        {
            "source": r["source"],
            "risk_type": r["risk_type"],
            "pattern": r["pattern"],
            "severity": r["severity"],
            "owasp_category": r["owasp_category"],
            "explanation": r["explanation"],
            "remediation": r["remediation"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_threat_intel_status() -> dict:
    with _conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c, MAX(created_at) AS last_updated FROM threat_intel_rules"
        ).fetchone()
    return {
        "rules_count": int(row["c"] or 0),
        "last_updated": row["last_updated"],
    }


def is_url_allowed(url: str, allowlist: list[str]) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if not allowlist:
            return False
        for domain in allowlist:
            d = domain.strip().lower()
            if not d:
                continue
            if host == d or host.endswith(f".{d}"):
                return True
        return False
    except Exception:
        return False
