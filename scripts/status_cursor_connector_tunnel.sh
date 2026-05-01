#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
ENV_FILE="${1:-$ROOT_DIR/.cursor_connector.env}"
HELPER_PID_FILE="$LOG_DIR/cursor_helper.pid"
NGROK_PID_FILE="$LOG_DIR/cursor_ngrok.pid"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

AISEC_LISTEN_HOST="${AISEC_LISTEN_HOST:-127.0.0.1}"
AISEC_LISTEN_PORT="${AISEC_LISTEN_PORT:-12345}"

print_proc() {
  local pid_file="$1"
  local name="$2"
  if [[ ! -f "$pid_file" ]]; then
    echo "$name: NOT RUNNING"
    return
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    echo "$name: RUNNING (PID: $pid)"
  else
    echo "$name: STALE PID FILE"
  fi
}

print_proc "$HELPER_PID_FILE" "helper"
print_proc "$NGROK_PID_FILE" "ngrok"

echo "Helper URL: http://${AISEC_LISTEN_HOST}:${AISEC_LISTEN_PORT}"
echo "Health:"
curl -s "http://${AISEC_LISTEN_HOST}:${AISEC_LISTEN_PORT}/health" || true
echo ""

if command -v curl >/dev/null 2>&1; then
  NGROK_URL="$(curl -s http://127.0.0.1:4040/api/tunnels | python3 -c 'import json,sys
try:
  data=json.load(sys.stdin)
  tunnels=data.get("tunnels",[])
  pub=next((t.get("public_url","") for t in tunnels if t.get("proto")=="https"),"")
  print(pub)
except Exception:
  print("")
')"
  if [[ -n "$NGROK_URL" ]]; then
    echo "ngrok public URL: $NGROK_URL"
  fi
fi

echo "Logs:"
echo "  $LOG_DIR/cursor_helper.log"
echo "  $LOG_DIR/cursor_ngrok.log"

