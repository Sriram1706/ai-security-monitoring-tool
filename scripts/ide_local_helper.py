#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib import error, request
from urllib.parse import urlparse

CURSOR_SCAFFOLD_MARKERS = [
    "<open_and_recently_viewed_files>",
    "</open_and_recently_viewed_files>",
    "<recently_viewed_files>",
    "</recently_viewed_files>",
    "<open_files>",
    "</open_files>",
    "user currently doesn't have any open files in their ide",
    "these files may or may not be relevant to the current conversation",
    "use the read fi",
    "open_and_recently_viewed_files",
]
SYSTEM_PROMPT_MARKERS = [
    "you are an ai coding assistant",
    "you operate in cursor",
    "the system may attach additional context",
    "help the user with software engineering tasks",
    "based on hidden context",
    "<system_reminder>",
    "you are a coding agent in the cursor ide",
    "the system may attach additional context from open files",
    "based on hidden context",
]
ASSISTANT_REPLY_MARKERS = [
    "it seems like your message got cut off",
    "how can i assist you today",
    "i can't share the system prompt",
    "i can't reveal system or hidden instructions",
    "blocked due to prompt injection risk",
]
EMBEDDED_USER_QUERY_PATTERNS = [
    re.compile(r"<user_query>\s*(.*?)\s*</user_query>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<user_message>\s*(.*?)\s*</user_message>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<prompt>\s*(.*?)\s*</prompt>", re.IGNORECASE | re.DOTALL),
    re.compile(r"(?:^|\n)\s*(?:user|prompt|question)\s*:\s*(.+)", re.IGNORECASE),
]


def estimate_tokens(text: str) -> int:
    stripped = str(text or "").strip()
    if not stripped:
        return 0
    return max(1, len(stripped.split()))


def _normalize_chat_content(content) -> str:
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") in {"text", "input_text", "output_text", "message_text"}:
                    text_value = block.get("text", "")
                    if isinstance(text_value, dict):
                        text_value = text_value.get("value", "")
                    parts.append(str(text_value))
                elif "text" in block:
                    text_value = block.get("text", "")
                    if isinstance(text_value, dict):
                        text_value = text_value.get("value", "")
                    parts.append(str(text_value))
                elif "parts" in block:
                    parts.append(_normalize_chat_content(block.get("parts", [])))
                elif "content" in block:
                    parts.append(_normalize_chat_content(block.get("content")))
                elif "value" in block:
                    parts.append(str(block.get("value", "")))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(part for part in parts if part).strip()
    if isinstance(content, dict):
        text_value = content.get("text", "") or content.get("input_text", "")
        if isinstance(text_value, dict):
            text_value = text_value.get("value", "")
        if text_value:
            return str(text_value).strip()
        if "parts" in content:
            parts_value = _normalize_chat_content(content.get("parts", []))
            if parts_value:
                return parts_value
        if "content" in content:
            nested = _normalize_chat_content(content.get("content"))
            if nested:
                return nested
        if "value" in content:
            return str(content.get("value", "")).strip()
        return ""
    return str(content or "").strip()


def _looks_like_cursor_scaffold(text: str) -> bool:
    raw = str(text or "").strip().lower()
    if not raw:
        return False
    return any(marker in raw for marker in CURSOR_SCAFFOLD_MARKERS)


def _is_placeholder_token(text: str) -> bool:
    raw = str(text or "").strip().lower()
    if not raw:
        return True
    if re.fullmatch(r"<[^>]{1,80}>", raw):
        return True
    return raw in {"<user_query>", "<user_message>", "<prompt>", "<query>", "<message>"}


def _looks_like_system_prompt_text(text: str) -> bool:
    raw = str(text or "").strip().lower()
    if not raw:
        return False
    return any(marker in raw for marker in SYSTEM_PROMPT_MARKERS)


def _looks_like_assistant_reply(text: str) -> bool:
    raw = str(text or "").strip().lower()
    if not raw:
        return False
    return any(marker in raw for marker in ASSISTANT_REPLY_MARKERS)


def _extract_embedded_user_query(text: str) -> str:
    raw = str(text or "")
    if not raw.strip():
        return ""

    for pattern in EMBEDDED_USER_QUERY_PATTERNS:
        matches = pattern.findall(raw)
        if not matches:
            continue
        for candidate in reversed(matches):
            value = str(candidate).strip()
            if not value:
                continue
            # Some regex variants can return tuples.
            if isinstance(candidate, tuple):
                value = " ".join(str(part).strip() for part in candidate if str(part).strip())
            sanitized = _sanitize_cursor_prompt(value)
            if sanitized and not _looks_like_assistant_reply(sanitized):
                return sanitized
            if value and not _is_placeholder_token(value) and not _looks_like_system_prompt_text(value):
                if not _looks_like_assistant_reply(value):
                    return value.strip()
    return ""


def _sanitize_cursor_prompt(text: str) -> str:
    """
    Remove Cursor IDE scaffold/context wrappers so policy evaluates the user's
    actual query instead of helper-generated context blocks.
    """
    raw = str(text or "").strip()
    if not raw:
        return ""

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    cleaned_lines = []
    for line in lines:
        lower = line.lower()
        if any(marker in lower for marker in CURSOR_SCAFFOLD_MARKERS):
            continue
        if _looks_like_system_prompt_text(line):
            continue
        if lower.startswith("<open_and_recently_viewed_files"):
            continue
        if lower.endswith("</open_and_recently_viewed_files>"):
            continue
        if "role': 'system'" in lower or '"role": "system"' in lower:
            continue
        if lower.startswith("system:") or lower.startswith("assistant:"):
            continue
        if _is_placeholder_token(line):
            continue
        if _looks_like_assistant_reply(line):
            continue
        cleaned_lines.append(line)

    if not cleaned_lines:
        return ""

    # Prefer explicit user-intent cues when present.
    for line in reversed(cleaned_lines):
        match = re.match(r"^(user|prompt|message|question)\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if match and match.group(2).strip():
            candidate = match.group(2).strip()
            if not _is_placeholder_token(candidate) and not _looks_like_system_prompt_text(candidate):
                return candidate

    for line in reversed(cleaned_lines):
        if not _is_placeholder_token(line) and not _looks_like_system_prompt_text(line):
            if _looks_like_assistant_reply(line):
                continue
            return line.strip()

    return ""


def _extract_latest_texts(value) -> tuple[str, str]:
    """
    Return (latest_user_text, latest_any_text) from unknown nested payloads.
    """
    if value is None:
        return "", ""
    if isinstance(value, str):
        stripped = value.strip()
        return "", stripped

    if isinstance(value, list):
        latest_user = ""
        latest_any = ""
        for item in value:
            if isinstance(item, dict):
                nested_user, nested_any = _extract_latest_texts(item)
                if nested_any:
                    latest_any = nested_any
                if nested_user:
                    latest_user = nested_user
            elif isinstance(item, str):
                latest_any = item.strip()
        return latest_user.strip(), latest_any.strip()

    if isinstance(value, dict):
        latest_user = ""
        latest_any = ""
        # Recurse all child values first so we can pick the final user turn
        # from deeply nested/variant payloads.
        for key, child in value.items():
            if key == "role":
                continue
            child_user, child_any = _extract_latest_texts(child)
            if child_any:
                latest_any = child_any
            if child_user:
                latest_user = child_user

        role = str(value.get("role", "")).strip().lower()
        content = _normalize_chat_content(value.get("content", ""))
        if not content:
            content = _normalize_chat_content(value.get("text", ""))
        if content:
            embedded_user = _extract_embedded_user_query(content)
            if embedded_user:
                latest_user = embedded_user
                latest_any = embedded_user
            else:
                latest_any = content
                if role in {"user", "human", "end_user", "client"}:
                    latest_user = content
        return latest_user.strip(), latest_any.strip()

    return "", str(value).strip()


def _extract_from_any_payload(value) -> str:
    """
    Extract best-effort latest user text from unknown payload shapes.
    Cursor can send variant objects where the user text is nested under
    prompt/input/messages structures rather than plain messages[].
    """
    latest_user, latest_any = _extract_latest_texts(value)
    candidate = (latest_user or latest_any).strip()
    sanitized = _sanitize_cursor_prompt(candidate)
    if sanitized:
        return sanitized
    if candidate and not _is_placeholder_token(candidate) and not _looks_like_system_prompt_text(candidate):
        return candidate

    pool: list[str] = []

    def _collect(node):
        if node is None:
            return
        if isinstance(node, str):
            pool.append(node)
            return
        if isinstance(node, list):
            for item in node:
                _collect(item)
            return
        if isinstance(node, dict):
            for child in node.values():
                _collect(child)

    _collect(value)
    for raw in reversed(pool):
        clean = _sanitize_cursor_prompt(raw)
        if clean:
            return clean
    return ""


def extract_prompt_from_chat_messages(messages) -> str:
    """
    Use the latest user turn for security evaluation.
    Cursor and similar clients resend full history on each request; scanning
    the entire transcript can cause stale malicious context to keep blocking
    safe follow-up turns.
    """
    user_candidates = []
    for item in messages or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "user")).strip().lower() or "user"
        content = _normalize_chat_content(item.get("content", ""))
        if not content:
            continue
        embedded_user = _extract_embedded_user_query(content)
        if embedded_user:
            user_candidates.append(embedded_user)
            continue

        if role in {"user", "human", "end_user", "client"}:
            user_candidates.append(content)

    for candidate in reversed(user_candidates):
        sanitized = _sanitize_cursor_prompt(candidate)
        if sanitized:
            return sanitized

    # If every user candidate looked like scaffold, only return fallback when
    # it is not placeholder/system text.
    if user_candidates:
        fallback = user_candidates[-1].strip()
        if not _is_placeholder_token(fallback) and not _looks_like_system_prompt_text(fallback):
            if _looks_like_assistant_reply(fallback):
                return ""
            return fallback
    return ""


def extract_prompt_from_responses_input(input_value) -> str:
    if isinstance(input_value, str):
        return input_value.strip()
    if isinstance(input_value, list):
        user_candidates = []
        latest_any = ""
        for item in input_value:
            if isinstance(item, dict):
                role = str(item.get("role", "user")).strip().lower() or "user"
                content = _normalize_chat_content(item.get("content", ""))
                if not content:
                    content = _normalize_chat_content(item.get("text", ""))
                if content:
                    embedded_user = _extract_embedded_user_query(content)
                    if embedded_user:
                        latest_any = embedded_user
                        user_candidates.append(embedded_user)
                        continue
                    latest_any = content
                    if role in {"user", "human", "end_user", "client"}:
                        user_candidates.append(content)
            else:
                latest_any = str(item).strip()
        for candidate in reversed(user_candidates):
            sanitized = _sanitize_cursor_prompt(candidate)
            if sanitized:
                return sanitized
        if user_candidates:
            fallback = user_candidates[-1].strip()
            if not _is_placeholder_token(fallback) and not _looks_like_system_prompt_text(fallback):
                return fallback
        return _sanitize_cursor_prompt(latest_any) or ""
    return _extract_from_any_payload(input_value)


class IdeLocalHelperHandler(BaseHTTPRequestHandler):
    server_version = "AISecurityIDEHelper/1.0"
    protocol_version = "HTTP/1.1"

    def _normalized_path(self) -> str:
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        # Normalize optional trailing slash so both /v1/chat/completions and /v1/chat/completions/
        # are handled identically.
        if path != "/":
            path = path.rstrip("/")
        return path

    def _json_response(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def _safe_error(self, status: int, message: str):
        """Best-effort error responder to avoid empty socket replies."""
        try:
            self._json_response({"error": {"message": message}}, status=status)
        except Exception:
            # If socket is already gone, just close silently.
            self.close_connection = True

    def _sse_send(self, payload: dict):
        data = json.dumps(payload)
        self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _stream_chat_completion(self, result: dict, requested_model: Optional[str] = None):
        content = str(result.get("response", ""))
        model_name = requested_model or result.get("provider") or self.server.default_model
        created = int(time.time())
        completion_id = f"chatcmpl-aisec-{uuid.uuid4().hex[:12]}"
        finish_reason = "content_filter" if bool(result.get("blocked")) else "stop"

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        self._sse_send(
            {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model_name,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant"},
                        "finish_reason": None,
                    }
                ],
            }
        )

        chunks = content.split() if content else [""]
        if not chunks:
            chunks = [""]
        for index, chunk in enumerate(chunks):
            text = chunk if index == len(chunks) - 1 else f"{chunk} "
            self._sse_send(
                {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_name,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": text},
                            "finish_reason": None,
                        }
                    ],
                }
            )

        self._sse_send(
            {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model_name,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": finish_reason,
                    }
                ],
                "aisec": {
                    "risk_score": result.get("risk_score", 0),
                    "risk_type": result.get("risk_type", "none"),
                    "severity": result.get("severity", "LOW"),
                    "status": result.get("status", "SAFE"),
                    "blocked": bool(result.get("blocked")),
                    "policy_reason": result.get("policy_reason"),
                    "policy_version": result.get("policy_version"),
                    "source": self.server.source,
                    "provider": self.server.provider,
                },
            }
        )
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True

    def _read_json(self):
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(content_length) if content_length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid JSON payload")

    def _gateway_process(self, prompt: str, model_name: Optional[str], upstream_body: dict):
        sys.stdout.write(f"[helper-forward] path={self.path} model={model_name or self.server.default_model} prompt={prompt[:180]!r}\n")
        sys.stdout.flush()
        payload = {
            "prompt": prompt,
            "provider": self.server.provider,
            "source": self.server.source,
            "model_name": model_name or self.server.default_model,
            "metadata": {
                "ide_name": self.server.ide_name,
                "helper_name": "ide_local_helper.py",
                "helper_version": "1.0",
                "upstream_path": self.path,
                "client": self.client_address[0],
                "request_headers": {
                    "user_agent": self.headers.get("User-Agent", ""),
                    "origin": self.headers.get("Origin", ""),
                },
                "upstream_request": upstream_body,
            },
        }
        req = request.Request(
            self.server.gateway_url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Connector-Key": self.server.connector_key,
            },
            data=json.dumps(payload).encode("utf-8"),
        )
        with request.urlopen(req, timeout=self.server.timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
        return json.loads(body)

    def _respond_chat_completion(self, result: dict, requested_model: Optional[str] = None):
        content = str(result.get("response", ""))
        model_name = requested_model or result.get("provider") or self.server.default_model
        prompt_tokens = estimate_tokens(str(result.get("prompt", "")))
        completion_tokens = estimate_tokens(content)
        response = {
            "id": f"chatcmpl-aisec-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model_name,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "content_filter" if bool(result.get("blocked")) else "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "aisec": {
                "risk_score": result.get("risk_score", 0),
                "risk_type": result.get("risk_type", "none"),
                "severity": result.get("severity", "LOW"),
                "status": result.get("status", "SAFE"),
                "blocked": bool(result.get("blocked")),
                "policy_reason": result.get("policy_reason"),
                "policy_version": result.get("policy_version"),
                "source": self.server.source,
                "provider": self.server.provider,
            },
        }
        self._json_response(response, status=200)

    def _respond_responses_api(self, result: dict, requested_model: Optional[str] = None):
        content = str(result.get("response", ""))
        model_name = requested_model or result.get("provider") or self.server.default_model
        prompt_tokens = estimate_tokens(str(result.get("prompt", "")))
        completion_tokens = estimate_tokens(content)
        response = {
            "id": f"resp-aisec-{uuid.uuid4().hex[:12]}",
            "object": "response",
            "created_at": int(time.time()),
            "status": "completed",
            "model": model_name,
            "output": [
                {
                    "id": f"msg-aisec-{uuid.uuid4().hex[:10]}",
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": content,
                            "annotations": [],
                        }
                    ],
                }
            ],
            "output_text": content,
            "usage": {
                "input_tokens": prompt_tokens,
                "output_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "aisec": {
                "risk_score": result.get("risk_score", 0),
                "risk_type": result.get("risk_type", "none"),
                "severity": result.get("severity", "LOW"),
                "status": result.get("status", "SAFE"),
                "blocked": bool(result.get("blocked")),
                "policy_reason": result.get("policy_reason"),
                "policy_version": result.get("policy_version"),
                "source": self.server.source,
                "provider": self.server.provider,
            },
        }
        self._json_response(response, status=200)

    def do_GET(self):
        try:
            path = self._normalized_path()
            if path in {"/health", "/healthz"}:
                self._json_response(
                    {
                        "status": "ok",
                        "gateway_url": self.server.gateway_url,
                        "source": self.server.source,
                        "provider": self.server.provider,
                        "ide_name": self.server.ide_name,
                    }
                )
                return
            if path in {"/v1/models", "/models"}:
                self._json_response(
                    {
                        "object": "list",
                        "data": [
                            {
                                "id": self.server.default_model,
                                "object": "model",
                                "owned_by": "ai-security-gateway",
                            }
                        ],
                    }
                )
                return
            self._json_response({"error": {"message": "Not found"}}, status=404)
        except Exception as exc:
            sys.stdout.write(f"[helper-error] method=GET path={self.path} error={exc}\n")
            sys.stdout.flush()
            self._safe_error(500, f"Local helper failure: {exc}")

    def do_OPTIONS(self):
        try:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
        except Exception as exc:
            sys.stdout.write(f"[helper-error] method=OPTIONS path={self.path} error={exc}\n")
            sys.stdout.flush()
            self._safe_error(500, f"Local helper failure: {exc}")

    def do_POST(self):
        try:
            path = self._normalized_path()
            try:
                body = self._read_json()
            except ValueError as exc:
                self._json_response({"error": {"message": str(exc)}}, status=400)
                return

            if path in {"/v1/chat/completions", "/chat/completions"}:
                prompt = extract_prompt_from_chat_messages(body.get("messages", []))
                if not prompt:
                    prompt = extract_prompt_from_responses_input(body.get("input"))
                if not prompt:
                    # Fallback for non-standard client payloads.
                    prompt = _extract_from_any_payload(body.get("prompt"))
                if not prompt:
                    prompt = _extract_from_any_payload(body.get("message"))
                if not prompt:
                    prompt = _extract_from_any_payload(body)
                if not prompt:
                    # Last fallback: any top-level text-like fields.
                    prompt = _extract_from_any_payload(body.get("text") or body.get("content"))
                    if not prompt:
                        self._json_response({"error": {"message": "No prompt content found in chat messages."}}, status=400)
                        return
                try:
                    result = self._gateway_process(prompt, body.get("model"), body)
                except error.HTTPError as exc:
                    message = exc.read().decode("utf-8", errors="ignore") or f"Gateway HTTP {exc.code}"
                    sys.stdout.write(f"[gateway-http-error] status={exc.code} path={path} body={message}\n")
                    sys.stdout.flush()
                    self._json_response({"error": {"message": message}}, status=502)
                    return
                except Exception as exc:
                    sys.stdout.write(f"[gateway-error] path={path} error={exc}\n")
                    sys.stdout.flush()
                    self._json_response({"error": {"message": f"Gateway request failed: {exc}"}}, status=502)
                    return
                if bool(body.get("stream")):
                    self._stream_chat_completion(result, requested_model=body.get("model"))
                    return
                self._respond_chat_completion(result, requested_model=body.get("model"))
                return

            if path in {"/v1/responses", "/responses"}:
                prompt = extract_prompt_from_responses_input(body.get("input"))
                if not prompt:
                    self._json_response({"error": {"message": "No input content found in responses payload."}}, status=400)
                    return
                try:
                    result = self._gateway_process(prompt, body.get("model"), body)
                except error.HTTPError as exc:
                    message = exc.read().decode("utf-8", errors="ignore") or f"Gateway HTTP {exc.code}"
                    sys.stdout.write(f"[gateway-http-error] status={exc.code} path={path} body={message}\n")
                    sys.stdout.flush()
                    self._json_response({"error": {"message": message}}, status=502)
                    return
                except Exception as exc:
                    sys.stdout.write(f"[gateway-error] path={path} error={exc}\n")
                    sys.stdout.flush()
                    self._json_response({"error": {"message": f"Gateway request failed: {exc}"}}, status=502)
                    return
                self._respond_responses_api(result, requested_model=body.get("model"))
                return

            self._json_response({"error": {"message": "Not found"}}, status=404)
        except Exception as exc:
            sys.stdout.write(f"[helper-error] method=POST path={self.path} error={exc}\n")
            sys.stdout.flush()
            self._safe_error(500, f"Local helper failure: {exc}")

    def log_message(self, format_str, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format_str % args))
        sys.stdout.flush()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run a local OpenAI-compatible helper for Cursor/Windsurf that forwards prompts to the AI Security gateway."
    )
    parser.add_argument("--listen-host", default="127.0.0.1", help="Local host to bind")
    parser.add_argument("--listen-port", type=int, default=8787, help="Local port to bind")
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("AISEC_GATEWAY_URL", "http://localhost:8000/gateway/process"),
        help="Gateway process endpoint",
    )
    parser.add_argument(
        "--connector-key",
        default=os.environ.get("AISEC_CONNECTOR_KEY", ""),
        help="Connector key from Gateway Connectors UI",
    )
    parser.add_argument("--source", default=os.environ.get("AISEC_SOURCE", "cursor-ide"), help="Connector source name")
    parser.add_argument("--provider", default=os.environ.get("AISEC_PROVIDER", "openai"), help="Upstream provider label")
    parser.add_argument("--ide-name", default=os.environ.get("AISEC_IDE_NAME", "cursor"), help="IDE label for metadata")
    parser.add_argument("--default-model", default=os.environ.get("AISEC_DEFAULT_MODEL", "gpt-4o-mini"), help="Fallback model name")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("AISEC_TIMEOUT_SEC", "30")), help="Gateway timeout in seconds")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.connector_key.strip():
        parser.error("A connector key is required. Pass --connector-key or set AISEC_CONNECTOR_KEY.")

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), IdeLocalHelperHandler)
    server.gateway_url = args.gateway_url
    server.connector_key = args.connector_key.strip()
    server.source = args.source
    server.provider = args.provider
    server.ide_name = args.ide_name
    server.default_model = args.default_model
    server.timeout = max(5, int(args.timeout))

    print(
        json.dumps(
            {
                "status": "ready",
                "listen": f"http://{args.listen_host}:{args.listen_port}",
                "gateway_url": args.gateway_url,
                "source": args.source,
                "provider": args.provider,
                "ide_name": args.ide_name,
                "default_model": args.default_model,
                "health": f"http://{args.listen_host}:{args.listen_port}/health",
            },
            indent=2,
        )
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down local IDE helper...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
