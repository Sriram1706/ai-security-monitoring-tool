#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT_DIR/logs/work_history_daemon.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Daemon is not running (no PID file)."
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ -n "$PID" ]] && kill -0 "$PID" >/dev/null 2>&1; then
  kill "$PID" >/dev/null 2>&1 || true
  sleep 1
  if kill -0 "$PID" >/dev/null 2>&1; then
    kill -9 "$PID" >/dev/null 2>&1 || true
  fi
  echo "Stopped daemon PID: $PID"
else
  echo "No active daemon process found for PID file."
fi

rm -f "$PID_FILE"

