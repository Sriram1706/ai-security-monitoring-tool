#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime
from urllib import request, error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a Cursor demo prompt into the AI Security Monitoring Tool mirror endpoint."
    )
    parser.add_argument("prompt", help="Prompt text to mirror into the monitoring tool")
    parser.add_argument("--endpoint", default="http://localhost:8000/mirror/cursor", help="Mirror endpoint URL")
    parser.add_argument("--workspace", default="", help="Optional workspace/repo name")
    parser.add_argument("--file", dest="file_path", default="", help="Optional file path")
    parser.add_argument("--provider", default="cursor_ide", help="Provider label to store")
    parser.add_argument("--source", default="cursor_ide", help="Source label to store")
    parser.add_argument("--mirror-key", default="", help="Optional X-Mirror-Key header value")
    args = parser.parse_args()

    payload = {
        "prompt": args.prompt,
        "source": args.source,
        "provider": args.provider,
        "page_url": "",
        "metadata": {
            "workspace": args.workspace,
            "file_path": args.file_path,
            "captured_at": datetime.utcnow().isoformat() + "Z",
            "connector": "cursor_demo_mirror.py",
        },
    }

    headers = {"Content-Type": "application/json"}
    if args.mirror_key:
        headers["X-Mirror-Key"] = args.mirror_key

    req = request.Request(
        args.endpoint,
        method="POST",
        headers=headers,
        data=json.dumps(payload).encode("utf-8"),
    )

    try:
        with request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            print(body)
            return 0
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        print(body or f"HTTP {exc.code}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
