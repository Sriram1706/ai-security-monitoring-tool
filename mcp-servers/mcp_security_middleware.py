import time
import hashlib
import json
import logging
from datetime import datetime
from functools import wraps
from collections import defaultdict

logging.basicConfig(
    filename="mcp-servers/audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

# In-memory rate limiter: server -> list of timestamps
_rate_limits = defaultdict(list)
RATE_LIMIT_MAX = 20
RATE_LIMIT_WINDOW = 60  # seconds

# Trusted MCP server identities
TRUSTED_SERVERS = {
    "mcp-scanner",
    "cve-lookup",
    "github-integration",
    "aws-scanner",
    "orchestrator"
}

# Prompt injection patterns to block
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "disregard all prior",
    "you are now",
    "forget your instructions",
    "system prompt",
    "jailbreak",
    "act as",
    "pretend you are",
    "override instructions",
]


def audit_log(server: str, tool: str, args: dict, result: str, blocked: bool = False):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "server": server,
        "tool": tool,
        "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:12],
        "result_length": len(result),
        "blocked": blocked
    }
    logging.info(json.dumps(log_entry))


def check_rate_limit(server: str) -> bool:
    now = time.time()
    timestamps = _rate_limits[server]
    # Remove timestamps outside window
    _rate_limits[server] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[server]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[server].append(now)
    return True


def sanitize_input(text: str) -> tuple[str, bool]:
    """Check for prompt injection. Returns (sanitized_text, was_injected)."""
    lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in lower:
            return text, True
    return text, False


def validate_server(server_id: str) -> bool:
    return server_id in TRUSTED_SERVERS


def secure_tool_call(server: str, tool: str):
    """Decorator that adds auth, rate limiting, sanitization, and audit logging."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 1. Validate server identity
            if not validate_server(server):
                audit_log(server, tool, kwargs, "BLOCKED: untrusted server", blocked=True)
                return f"Security Error: Untrusted server '{server}'"

            # 2. Rate limiting
            if not check_rate_limit(server):
                audit_log(server, tool, kwargs, "BLOCKED: rate limit exceeded", blocked=True)
                return f"Security Error: Rate limit exceeded for '{server}'"

            # 3. Input sanitization — check all string args
            for key, val in kwargs.items():
                if isinstance(val, str):
                    _, injected = sanitize_input(val)
                    if injected:
                        audit_log(server, tool, kwargs, "BLOCKED: prompt injection", blocked=True)
                        return f"Security Error: Prompt injection detected in argument '{key}'"

            # 4. Execute tool
            result = func(*args, **kwargs)

            # 5. Audit log successful call
            audit_log(server, tool, kwargs, str(result))
            return result
        return wrapper
    return decorator


def get_audit_log(lines: int = 20) -> list:
    """Read last N lines from audit log."""
    try:
        with open("mcp-servers/audit.log") as f:
            all_lines = f.readlines()
            return [json.loads(l.split(" | ", 1)[1]) for l in all_lines[-lines:] if " | " in l]
    except Exception:
        return []
