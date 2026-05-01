#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$LOG_DIR/work_history_daemon.pid"
DAEMON_LOG="$LOG_DIR/work_history_daemon.log"
INTERVAL_SECONDS="${1:-1800}"

mkdir -p "$LOG_DIR"

if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "${OLD_PID}" ]] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    echo "Daemon already running (PID: $OLD_PID)"
    exit 0
  fi
fi

nohup /bin/bash -lc "
  export PATH=\"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\"
  while true; do
    /usr/bin/env python3 \"$ROOT_DIR/scripts/auto_capture_work_history.py\" --note \"Background auto capture\" >>\"$DAEMON_LOG\" 2>&1 || true
    sleep \"$INTERVAL_SECONDS\"
  done
" >/dev/null 2>&1 &

echo $! >"$PID_FILE"
echo "Work history daemon started. PID: $(cat "$PID_FILE")"
echo "Interval: ${INTERVAL_SECONDS}s"
echo "Log: $DAEMON_LOG"

