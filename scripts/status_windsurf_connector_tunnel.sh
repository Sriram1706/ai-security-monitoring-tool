#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${1:-$ROOT_DIR/.windsurf_connector.env}"

exec "$ROOT_DIR/scripts/status_cursor_connector_tunnel.sh" "$ENV_FILE"

