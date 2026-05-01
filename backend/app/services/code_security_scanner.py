from __future__ import annotations

import re
from typing import Any


def _normalize_text(value: str | None) -> str:
    text = str(value or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


RULES: list[dict[str, Any]] = [
    {
        "finding_type": "hardcoded_secret",
        "severity": "CRITICAL",
        "title": "Hardcoded API key or token",
        "patterns": [
            r"sk-[a-zA-Z0-9]{20,}",
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        ],
        "explanation": "The code or prompt appears to expose a hardcoded secret/token.",
        "remediation": "Move secrets to environment variables or a vault and rotate exposed keys immediately.",
    },
    {
        "finding_type": "authn_authz",
        "severity": "HIGH",
        "title": "Authentication or authorization bypass pattern",
        "patterns": [
            r"(?i)verify\s*=\s*False",
            r"(?i)allow_all",
            r"(?i)admin(_role)?\s*=\s*true",
            r"(?i)if\s+user\.role\s*==\s*['\"]admin['\"]\s*:\s*pass",
            r"(?i)disable_auth",
        ],
        "explanation": "The logic suggests permissive authentication/authorization behavior.",
        "remediation": "Enforce server-side auth checks, least privilege, and role validation per request.",
    },
    {
        "finding_type": "sql_injection",
        "severity": "HIGH",
        "title": "Potential SQL injection pattern",
        "patterns": [
            r"(?i)execute\(\s*f[\"']",
            r"(?i)select\s+.+\s+from\s+.+\+\s*",
            r"(?i)where\s+.+\s*=\s*['\"].*\+",
            r"(?i)cursor\.execute\(\s*['\"].*%s.*['\"]\s*%",
        ],
        "explanation": "Dynamic SQL concatenation can allow untrusted input to alter queries.",
        "remediation": "Use parameterized queries/ORM binding and strict input validation.",
    },
    {
        "finding_type": "command_injection",
        "severity": "HIGH",
        "title": "Potential command injection pattern",
        "patterns": [
            r"(?i)os\.system\(",
            r"(?i)subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True",
            r"(?i)eval\(",
            r"(?i)exec\(",
        ],
        "explanation": "Unsafely invoking system commands or dynamic execution is high-risk.",
        "remediation": "Avoid shell invocation, sanitize/allowlist inputs, and use safe APIs without eval/exec.",
    },
    {
        "finding_type": "xss_output_encoding",
        "severity": "MEDIUM",
        "title": "Potential XSS/output encoding gap",
        "patterns": [
            r"(?i)dangerouslySetInnerHTML",
            r"(?i)innerHTML\s*=",
            r"(?i)document\.write\(",
        ],
        "explanation": "Unsanitized HTML rendering can enable script injection in clients.",
        "remediation": "Use output encoding/sanitization libraries and avoid raw HTML sinks.",
    },
    {
        "finding_type": "missing_rate_limit",
        "severity": "MEDIUM",
        "title": "Potential missing rate limit or abuse control",
        "patterns": [
            r"(?i)(login|auth|token|otp|password).*endpoint",
            r"(?i)(no rate limit|without rate limit|unlimited requests)",
            r"(?i)public api endpoint",
        ],
        "explanation": "Sensitive/API endpoints may lack brute-force and abuse protections.",
        "remediation": "Apply IP/user rate limits, request quotas, and anomaly detection.",
    },
    {
        "finding_type": "insecure_dependency",
        "severity": "MEDIUM",
        "title": "Potential insecure dependency/version pattern",
        "patterns": [
            r"(?i)\brequirements\.txt\b.*(django==1\.|flask==0\.|requests==2\.1)",
            r"(?i)npm install .* --force",
            r"(?i)latest\s+without\s+pinning",
            r"(?i)dependency\s+integrity\s+disabled",
        ],
        "explanation": "Unpinned/outdated dependencies increase supply chain risk.",
        "remediation": "Pin versions, run SCA scanning, and enforce dependency review gates.",
    },
]


def scan_code_security(content: str | None, context: str = "response") -> list[dict[str, Any]]:
    text = _normalize_text(content)
    if not text.strip():
        return []

    findings: list[dict[str, Any]] = []
    lowered = text.lower()

    for rule in RULES:
        matched_evidence: str | None = None
        for pattern in rule["patterns"]:
            match = re.search(pattern, text, flags=re.MULTILINE)
            if match:
                matched_evidence = match.group(0)[:240]
                break

        if not matched_evidence:
            continue

        confidence = 0.75
        if rule["severity"] in {"CRITICAL", "HIGH"}:
            confidence = 0.9
        if "```" in lowered:
            confidence = min(0.99, confidence + 0.04)

        findings.append(
            {
                "context": context,
                "finding_type": rule["finding_type"],
                "severity": rule["severity"],
                "title": rule["title"],
                "explanation": rule["explanation"],
                "remediation": rule["remediation"],
                "evidence": matched_evidence,
                "confidence": round(confidence, 2),
            }
        )

    return findings

