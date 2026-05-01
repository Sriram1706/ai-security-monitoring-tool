#!/usr/bin/env bash
set -euo pipefail

LABEL="com.ai_security_monitoring_tool.daily_backup"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
UID_VALUE="$(id -u)"

if [[ -f "$PLIST_PATH" ]]; then
  launchctl bootout "gui/${UID_VALUE}" "$PLIST_PATH" >/dev/null 2>&1 || true
  rm -f "$PLIST_PATH"
  echo "Uninstalled LaunchAgent: $LABEL"
else
  echo "No LaunchAgent found at: $PLIST_PATH"
fi

