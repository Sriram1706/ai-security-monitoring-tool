#!/usr/bin/env bash
set -euo pipefail

LABEL="com.ai_security_monitoring_tool.work_history_capture"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
UID_VALUE="$(id -u)"

echo "Label: $LABEL"
echo "Plist: $PLIST_PATH"

if [[ ! -f "$PLIST_PATH" ]]; then
  echo "Status: NOT INSTALLED"
  exit 0
fi

echo "Status: INSTALLED"
launchctl print "gui/${UID_VALUE}/${LABEL}" | sed -n '1,50p'

