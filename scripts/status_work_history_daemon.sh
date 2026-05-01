#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT_DIR/logs/work_history_daemon.pid"
LOG_FILE="$ROOT_DIR/logs/work_history_daemon.log"
STATE_FILE="$ROOT_DIR/docs/.work_history_state.json"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Status: NOT RUNNING"
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ -n "$PID" ]] && kill -0 "$PID" >/dev/null 2>&1; then
  echo "Status: RUNNING"
  echo "PID: $PID"
else
  echo "Status: STALE PID FILE"
fi

echo "PID file: $PID_FILE"
echo "State file: $STATE_FILE"
echo "Daemon log: $LOG_FILE"
if [[ -f "$LOG_FILE" ]]; then
  echo "--- Recent daemon log ---"
  tail -n 20 "$LOG_FILE"
fi

