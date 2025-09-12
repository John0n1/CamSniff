#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

echo "[INFO] Python core tests"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[SKIP] python3 not available"
  exit 0
fi

# Clean previous DB/logs
rm -rf output

# Init DB via module
python3 python_core/cli.py initdb >/dev/null 2>&1 || { echo "[ERROR] cli initdb failed"; exit 1; }

[[ -f output/results.sqlite ]] || { echo "[ERROR] results.sqlite not created"; exit 1; }

# Probe command should not crash (target local loopback; expect no results but no exceptions)
python3 python_core/cli.py probe-http --ip 127.0.0.1 --port 65500 >/dev/null 2>&1 || { echo "[ERROR] probe-http raised error"; exit 1; }

# Web backend should import and expose app
python3 - <<'PY'
import sys
from python_core import web_backend
assert hasattr(web_backend, 'app'), 'web_backend.app missing'
print('OK')
PY

echo "[PASS] Python core tests OK"
