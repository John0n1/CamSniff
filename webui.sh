#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"

VENV_DIR="$ROOT_DIR/.camvenv"
export CAMSNIFF_OUTPUT="$ROOT_DIR/output"
export CAMSNIFF_WEB_PORT="${CAMSNIFF_WEB_PORT:-8088}"

if [[ -d "$VENV_DIR" ]]; then
  source "$VENV_DIR/bin/activate"
fi

pip show flask >/dev/null 2>&1 || pip install --quiet flask
echo "[INFO] Web UI listening on http://localhost:$CAMSNIFF_WEB_PORT"
python3 "$ROOT_DIR/web/app.py"
