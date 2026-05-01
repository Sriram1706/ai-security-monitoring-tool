# AI Code Security Scanner

This module adds code-focused security detection on top of prompt risk scanning.

## What It Detects

- `hardcoded_secret` (critical)
- `authn_authz` (high)
- `sql_injection` (high)
- `command_injection` (high)
- `xss_output_encoding` (medium)
- `missing_rate_limit` (medium)
- `insecure_dependency` (medium)

## Runtime Flow

1. User prompt hits `/process-prompt` or `/gateway/process`.
2. Prompt risk engine runs (existing behavior).
3. LLM response is generated or blocked (existing policy behavior).
4. Code scanner analyzes both prompt and response text.
5. Findings are persisted in SQLite table `code_findings`.

## New APIs

- `GET /code-findings`
  - Query params:
    - `finding_type`
    - `severity`
    - `provider`
    - `source`
    - `limit` (1..1000)
- `GET /code-findings/summary`
  - Returns:
    - `total_findings`
    - `findings_last_24h`
    - `severity_distribution`
    - `top_finding_types`

## SQLite Table

`code_findings` fields:

- `id`
- `log_id`
- `prompt`
- `finding_type`
- `severity`
- `title`
- `explanation`
- `remediation`
- `evidence`
- `confidence`
- `provider`
- `source`
- `endpoint`
- `timestamp`
- `metadata`

## Frontend

Requests page now includes:

- Total code findings
- Findings in last 24h
- Critical and High counts
- Top finding types chips
