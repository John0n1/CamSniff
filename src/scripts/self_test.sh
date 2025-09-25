#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION_FILE="$REPO_ROOT/../VERSION"
VERSION="$(cat "$REPO_ROOT/../VERSION" 2>/dev/null || echo dev)"

json_escape(){ python3 - <<'PY' "$1" 2>/dev/null || printf '%s' "$1" | sed 's/"/\\"/g'
import json,sys;print(json.dumps(sys.argv[1]))
PY
}

status(){ local k="$1" v="$2"; printf '  "%s": %s,\n' "$k" "$v"; }

deps=(bash python3 jq curl ffmpeg masscan nmap hydra)
missing=()
for d in "${deps[@]}"; do command -v "$d" >/dev/null 2>&1 || missing+=("$d"); done

WORDLIST_OK=0
[[ -f "$REPO_ROOT/passwords.txt" && -s "$REPO_ROOT/passwords.txt" ]] && WORDLIST_OK=1 || true
[[ -f "$REPO_ROOT/usernames.txt" && -s "$REPO_ROOT/usernames.txt" ]] || WORDLIST_OK=0

RTSP_OK=0
[[ -f "$REPO_ROOT/rtsp_paths.csv" ]] && RTSP_OK=1 || true

cat <<EOF
{
  "version": "${VERSION}",
  "timestamp": "$(date -Iseconds)",
  "dependencies_present": $(( ${#missing[@]}==0 ? 1 : 0 )),
  "missing_dependencies": [$(printf '"%s",' "${missing[@]}" | sed 's/,$//')],
  "wordlists_ok": ${WORDLIST_OK},
  "rtsp_paths_present": ${RTSP_OK},
  "bin_wrapper": $([[ -x "$REPO_ROOT/../bin/camsniff" ]] && echo 1 || echo 0)
}
EOF

exit 0