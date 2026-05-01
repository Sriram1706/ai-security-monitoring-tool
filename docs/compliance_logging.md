# Logging, Audit, and Compliance Strategy (GDPR + SOC2)

## Logging Strategy
- Log every prompt/response scan with risk findings (`scan_logs`)
- Store actor identity, action type, and scan linkage in `audit_logs`
- Maintain hash chain (`prev_hash`, `event_hash`) for tamper evidence
- Use UTC timestamps and append-only write patterns

## GDPR Controls
- Data minimization: store only required fields
- Purpose limitation: security monitoring only
- Pseudonymization option for user identifiers in metadata
- Data retention policy (e.g., 90 days raw, 1 year aggregated)
- Right to erasure workflow by subject identifier (where lawful)

## SOC2 Controls
- RBAC (`admin`, `analyst`) with JWT auth
- Immutable audit verification endpoint
- Centralized metrics and alerting
- CI checks and reproducible deployments via Docker

## Example Queries
Top critical incidents (24h):
```sql
SELECT id, provider, risk_score, created_at
FROM scan_logs
WHERE severity = 'critical'
  AND created_at >= NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;
```

Prompt injection trend by day:
```sql
SELECT DATE(created_at) AS day, COUNT(*)
FROM scan_logs
WHERE findings::text ILIKE '%prompt_injection%'
GROUP BY DATE(created_at)
ORDER BY day DESC;
```

Audit chain gap check:
```sql
SELECT id, prev_hash, event_hash
FROM audit_logs
ORDER BY id ASC;
```
