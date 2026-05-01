#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="$ROOT_DIR/backups"

if [[ ! -d "$BACKUP_DIR" ]]; then
  echo "No backups directory found: $BACKUP_DIR"
  exit 0
fi

ls -lh "$BACKUP_DIR"/security_*.db 2>/dev/null || echo "No security DB backups found."
