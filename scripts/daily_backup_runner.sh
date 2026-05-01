#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_SCRIPT="$ROOT_DIR/scripts/backup_security_db.sh"
BACKUP_DIR="$ROOT_DIR/backups"
LOG_DIR="$BACKUP_DIR/logs"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
LOG_FILE="$LOG_DIR/daily_backup.log"

mkdir -p "$BACKUP_DIR" "$LOG_DIR"

{
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting daily backup..."
  "$BACKUP_SCRIPT"
  find "$BACKUP_DIR" -name "security_*.db" -type f -mtime +"$RETENTION_DAYS" -delete
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup complete. Retention: ${RETENTION_DAYS} days"
} >>"$LOG_FILE" 2>&1

