#!/bin/bash

TIMESTAMP=$(date +%F_%H-%M)
BACKUP_FILE="backup_$TIMESTAMP.sql"

# FULL path (important for cron)
BACKUP_DIR="/Users/snarayanan/Documents/AI Security/ai_security_monitoring_tool/deploy/backups"

# Create backup
docker exec -t deploy-db-1 pg_dump -U postgres ai_sec > "$BACKUP_DIR/$BACKUP_FILE"

echo "Backup created: $BACKUP_FILE"

echo "Backup created at $(date)" >> "$BACKUP_DIR/backup.log"
