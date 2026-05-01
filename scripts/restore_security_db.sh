#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backup_db_path>"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DB_PATH="$ROOT_DIR/security.db"
BACKUP_FILE="$1"

if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "ERROR: backup file not found: $BACKUP_FILE"
  exit 1
fi

cp "$BACKUP_FILE" "$DB_PATH"
echo "Restored security.db from: $BACKUP_FILE"
echo "Now restart backend:"
echo "  cd \"$ROOT_DIR/deploy\" && docker compose restart backend"
