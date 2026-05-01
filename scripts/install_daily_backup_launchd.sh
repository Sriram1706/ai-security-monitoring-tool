#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="com.ai_security_monitoring_tool.daily_backup"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$LAUNCH_AGENTS_DIR/${LABEL}.plist"
APP_SUPPORT_DIR="$HOME/Library/Application Support/ai_security_monitoring_tool"
RUNNER_SCRIPT="$APP_SUPPORT_DIR/daily_backup_runner.sh"
BACKUP_DIR="$APP_SUPPORT_DIR/backups"
LOG_DIR="$BACKUP_DIR/logs"
OUT_LOG="$BACKUP_DIR/launchd.out.log"
ERR_LOG="$BACKUP_DIR/launchd.err.log"
HOUR="${1:-1}"
MINUTE="${2:-0}"
UID_VALUE="$(id -u)"
DOCKER_BIN="$(command -v docker || true)"

mkdir -p "$LAUNCH_AGENTS_DIR" "$APP_SUPPORT_DIR" "$BACKUP_DIR" "$LOG_DIR"

cat >"$RUNNER_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$ROOT_DIR"
DB_PATH="\$ROOT_DIR/security.db"
BACKUP_DIR="$BACKUP_DIR"
LOG_FILE="$LOG_DIR/daily_backup.log"
RETENTION_DAYS="\${RETENTION_DAYS:-30}"
TIMESTAMP="\$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="\$BACKUP_DIR/security_\${TIMESTAMP}.db"
DOCKER_BIN="$DOCKER_BIN"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
mkdir -p "\$BACKUP_DIR" "$LOG_DIR"
{
  echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Starting daily backup..."
  if [[ -f "\$DB_PATH" ]]; then
    cp "\$DB_PATH" "\$BACKUP_FILE" || true
  fi
  if [[ ! -f "\$BACKUP_FILE" ]]; then
    if [[ -n "\$DOCKER_BIN" && -x "\$DOCKER_BIN" && -d "\$ROOT_DIR/deploy" ]]; then
      echo "Filesystem copy unavailable. Trying Docker fallback via \$DOCKER_BIN..."
      (cd "\$ROOT_DIR/deploy" && "\$DOCKER_BIN" compose cp backend:/security.db "\$BACKUP_FILE") || true
    else
      echo "Docker fallback not available (DOCKER_BIN=\$DOCKER_BIN)."
    fi
  fi
  if [[ ! -f "\$BACKUP_FILE" ]]; then
    echo "ERROR: unable to create backup from filesystem or Docker backend"
    exit 1
  fi
  find "\$BACKUP_DIR" -name "security_*.db" -type f -mtime +"\$RETENTION_DAYS" -delete
  echo "Backup created: \$BACKUP_FILE"
  echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Backup complete. Retention: \${RETENTION_DAYS} days"
} >>"$LOG_DIR/daily_backup.log" 2>&1
EOF

chmod +x "$RUNNER_SCRIPT"

cat >"$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$RUNNER_SCRIPT</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>$HOUR</integer>
    <key>Minute</key>
    <integer>$MINUTE</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>$OUT_LOG</string>
  <key>StandardErrorPath</key>
  <string>$ERR_LOG</string>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
EOF

# Reload agent if already present
launchctl bootout "gui/${UID_VALUE}" "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap "gui/${UID_VALUE}" "$PLIST_PATH"
launchctl enable "gui/${UID_VALUE}/${LABEL}" >/dev/null 2>&1 || true

echo "Installed daily backup LaunchAgent:"
echo "  Label: $LABEL"
echo "  Time: $(printf '%02d:%02d' "$HOUR" "$MINUTE") daily"
echo "  Plist: $PLIST_PATH"
echo "  Runner: $RUNNER_SCRIPT"
echo "  Backups: $BACKUP_DIR"
echo "  Logs: $OUT_LOG / $ERR_LOG / $LOG_DIR/daily_backup.log"
