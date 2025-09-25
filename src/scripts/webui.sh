#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${_CAMSNIFF_WEBUI_RAN:-}" ]]; then
  exit 0
fi
_CAMSNIFF_WEBUI_RAN=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$ROOT_DIR/.camvenv"

export CAMSNIFF_OUTPUT="${CAMSNIFF_OUTPUT:-$ROOT_DIR/output}"
export CAMSNIFF_WEB_PORT="${CAMSNIFF_WEB_PORT:-8088}"

if [[ -d "$VENV_DIR" ]]; then
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
fi

if ! python3 -c 'import flask' >/dev/null 2>&1; then
  pip install --quiet flask
fi
echo "[INFO] Web UI listening on http://localhost:$CAMSNIFF_WEB_PORT (output=$CAMSNIFF_OUTPUT)"
exec python3 "$ROOT_DIR/src/python_core/app.py"
