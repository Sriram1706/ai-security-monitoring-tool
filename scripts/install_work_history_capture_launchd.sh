#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="com.ai_security_monitoring_tool.work_history_capture"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$LAUNCH_AGENTS_DIR/${LABEL}.plist"
APP_SUPPORT_DIR="$HOME/Library/Application Support/ai_security_monitoring_tool"
RUNNER_SCRIPT="$APP_SUPPORT_DIR/work_history_capture_runner.sh"
OUT_LOG="$APP_SUPPORT_DIR/work_history_capture.launchd.out.log"
ERR_LOG="$APP_SUPPORT_DIR/work_history_capture.launchd.err.log"
INTERVAL_MINUTES="${1:-120}"
INTERVAL_SECONDS="$((INTERVAL_MINUTES * 60))"
UID_VALUE="$(id -u)"

mkdir -p "$LAUNCH_AGENTS_DIR" "$APP_SUPPORT_DIR"

cat >"$RUNNER_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$ROOT_DIR"
RUNNER="\$ROOT_DIR/scripts/work_history_capture_runner.sh"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
if [[ -x "\$RUNNER" ]]; then
  "\$RUNNER"
else
  /bin/bash "\$RUNNER"
fi
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
  <key>StartInterval</key>
  <integer>$INTERVAL_SECONDS</integer>
  <key>StandardOutPath</key>
  <string>$OUT_LOG</string>
  <key>StandardErrorPath</key>
  <string>$ERR_LOG</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF

launchctl bootout "gui/${UID_VALUE}" "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap "gui/${UID_VALUE}" "$PLIST_PATH"
launchctl enable "gui/${UID_VALUE}/${LABEL}" >/dev/null 2>&1 || true

echo "Installed work history auto-capture LaunchAgent:"
echo "  Label: $LABEL"
echo "  Interval: every ${INTERVAL_MINUTES} minute(s)"
echo "  Plist: $PLIST_PATH"
echo "  Runner: $RUNNER_SCRIPT"
echo "  Logs: $OUT_LOG / $ERR_LOG"

