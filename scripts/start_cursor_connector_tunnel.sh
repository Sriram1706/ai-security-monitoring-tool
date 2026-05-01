#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
ENV_FILE="${1:-$ROOT_DIR/.cursor_connector.env}"

HELPER_PID_FILE="$LOG_DIR/cursor_helper.pid"
NGROK_PID_FILE="$LOG_DIR/cursor_ngrok.pid"
HELPER_LOG="$LOG_DIR/cursor_helper.log"
NGROK_LOG="$LOG_DIR/cursor_ngrok.log"

mkdir -p "$LOG_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Config file not found: $ENV_FILE"
  echo "Create it from: $ROOT_DIR/scripts/cursor_connector.env.example"
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

if [[ -z "${AISEC_CONNECTOR_KEY:-}" || "${AISEC_CONNECTOR_KEY}" == "replace_with_rotated_connector_key" ]]; then
  echo "AISEC_CONNECTOR_KEY is missing or placeholder. Update $ENV_FILE first."
  exit 1
fi

AISEC_SOURCE="${AISEC_SOURCE:-cursor-ide}"
AISEC_PROVIDER="${AISEC_PROVIDER:-openai}"
AISEC_IDE_NAME="${AISEC_IDE_NAME:-cursor}"
AISEC_LISTEN_HOST="${AISEC_LISTEN_HOST:-127.0.0.1}"
AISEC_LISTEN_PORT="${AISEC_LISTEN_PORT:-12345}"
AISEC_DEFAULT_MODEL="${AISEC_DEFAULT_MODEL:-gpt-4o-mini}"
AISEC_TIMEOUT_SEC="${AISEC_TIMEOUT_SEC:-30}"
AISEC_GATEWAY_URL="${AISEC_GATEWAY_URL:-http://localhost:8000/gateway/process}"
ENABLE_NGROK="${ENABLE_NGROK:-1}"
NGROK_PORT="${NGROK_PORT:-$AISEC_LISTEN_PORT}"

if [[ -f "$HELPER_PID_FILE" ]]; then
  OLD_PID="$(cat "$HELPER_PID_FILE" 2>/dev/null || true)"
  if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    echo "Helper already running (PID: $OLD_PID)"
  fi
fi

if ! [[ -f "$HELPER_PID_FILE" ]] || ! kill -0 "$(cat "$HELPER_PID_FILE" 2>/dev/null || echo 0)" >/dev/null 2>&1; then
  nohup /usr/bin/env python3 "$ROOT_DIR/scripts/ide_local_helper.py" \
    --gateway-url "$AISEC_GATEWAY_URL" \
    --connector-key "$AISEC_CONNECTOR_KEY" \
    --source "$AISEC_SOURCE" \
    --provider "$AISEC_PROVIDER" \
    --ide-name "$AISEC_IDE_NAME" \
    --listen-host "$AISEC_LISTEN_HOST" \
    --listen-port "$AISEC_LISTEN_PORT" \
    --default-model "$AISEC_DEFAULT_MODEL" \
    --timeout "$AISEC_TIMEOUT_SEC" \
    >>"$HELPER_LOG" 2>&1 &
  echo $! >"$HELPER_PID_FILE"
  echo "Started helper PID $(cat "$HELPER_PID_FILE")"
fi

if [[ "$ENABLE_NGROK" == "1" ]]; then
  if ! command -v ngrok >/dev/null 2>&1; then
    echo "ngrok not found in PATH. Helper started, ngrok skipped."
  else
    if [[ -f "$NGROK_PID_FILE" ]]; then
      OLD_NGROK_PID="$(cat "$NGROK_PID_FILE" 2>/dev/null || true)"
      if [[ -n "$OLD_NGROK_PID" ]] && kill -0 "$OLD_NGROK_PID" >/dev/null 2>&1; then
        echo "ngrok already running (PID: $OLD_NGROK_PID)"
      fi
    fi
    if ! [[ -f "$NGROK_PID_FILE" ]] || ! kill -0 "$(cat "$NGROK_PID_FILE" 2>/dev/null || echo 0)" >/dev/null 2>&1; then
      nohup ngrok http "$NGROK_PORT" >>"$NGROK_LOG" 2>&1 &
      echo $! >"$NGROK_PID_FILE"
      echo "Started ngrok PID $(cat "$NGROK_PID_FILE")"
    fi
  fi
fi

echo ""
echo "Helper health:"
echo "  curl http://${AISEC_LISTEN_HOST}:${AISEC_LISTEN_PORT}/health"
echo "Logs:"
echo "  $HELPER_LOG"
echo "  $NGROK_LOG"
echo "Status:"
echo "  $ROOT_DIR/scripts/status_cursor_connector_tunnel.sh \"$ENV_FILE\""

