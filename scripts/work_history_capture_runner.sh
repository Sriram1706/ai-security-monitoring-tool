#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/work_history_capture.log"
NOTE="${WORK_HISTORY_NOTE:-Scheduled auto capture}"

mkdir -p "$LOG_DIR"

{
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting work history capture..."
  /usr/bin/env python3 "$ROOT_DIR/scripts/auto_capture_work_history.py" --note "$NOTE"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Work history capture complete."
} >>"$LOG_FILE" 2>&1

