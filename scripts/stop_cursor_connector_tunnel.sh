#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
HELPER_PID_FILE="$LOG_DIR/cursor_helper.pid"
NGROK_PID_FILE="$LOG_DIR/cursor_ngrok.pid"

stop_pid_file() {
  local pid_file="$1"
  local name="$2"
  if [[ ! -f "$pid_file" ]]; then
    echo "$name not running (no PID file)."
    return 0
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    sleep 1
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
    echo "Stopped $name PID: $pid"
  else
    echo "$name PID file exists but process not running."
  fi
  rm -f "$pid_file"
}

stop_pid_file "$HELPER_PID_FILE" "helper"
stop_pid_file "$NGROK_PID_FILE" "ngrok"

