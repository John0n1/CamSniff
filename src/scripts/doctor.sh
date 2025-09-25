#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

YELLOW='\033[33m'; GREEN='\033[32m'; RED='\033[31m'; CYAN='\033[36m'; RESET='\033[0m'
ok(){ echo -e "${GREEN}[OK]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${RESET} $*"; }
err(){ echo -e "${RED}[ERR]${RESET} $*"; }
info(){ echo -e "${CYAN}[INFO]${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION_FILE="$REPO_ROOT/../VERSION"
VERSION="$(cat "$VERSION_FILE" 2>/dev/null || echo dev)"

START_TS="$(date -Iseconds)"

echo "CamSniff Doctor (${VERSION})"
echo "--------------------------------"

# Detect OS info
OS_PRETTY="$(grep PRETTY_NAME= /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -a)"
info "OS: $OS_PRETTY"

if command -v apt-get >/dev/null 2>&1; then
  ok "apt-get present"
else
  warn "apt-get not found (non-Debian env). Some automated installs may fail."
fi

# Required & recommended tools
declare -a req_tools=(jq curl ffmpeg python3)
declare -a rec_tools=(fping masscan nmap hydra tshark arp-scan avahi-browse gobuster onesixtyone)
missing_req=(); missing_rec=()
for t in "${req_tools[@]}"; do command -v "$t" >/dev/null 2>&1 || missing_req+=("$t"); done
for t in "${rec_tools[@]}"; do command -v "$t" >/dev/null 2>&1 || missing_rec+=("$t"); done

if (( ${#missing_req[@]} )); then
  err "Missing required tools: ${missing_req[*]}"
else
  ok "All required tools present"
fi

if (( ${#missing_rec[@]} )); then
  warn "Missing recommended tools: ${missing_rec[*]}"
else
  ok "All recommended tools present"
fi

# Version capture for present tools
tool_versions_json="{"
first=1
for t in "${req_tools[@]}" "${rec_tools[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    v=$( ("$t" --version 2>&1 || true) | head -n1 | tr '"' "'" )
    [[ $first -eq 0 ]] && tool_versions_json+=" ,"
    tool_versions_json+="\n    \"$t\": \"$v\""
    first=0
  fi
done
tool_versions_json+="\n  }"

# Python environment / virtualenv
VENV_DIR="$REPO_ROOT/.camvenv"
PY_STATUS="none"
py_missing=()
if command -v python3 >/dev/null 2>&1; then
  PY_VER=$(python3 -c 'import sys;print(sys.version.split()[0])')
  if [[ -d "$VENV_DIR" ]]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate" || true
    PY_STATUS="venv"
  else
    PY_STATUS="system"
  fi
  for pkg in requests flask; do
    python3 -c "import $pkg" >/dev/null 2>&1 || py_missing+=("$pkg")
  done
else
  PY_VER="unavailable"
fi

if [[ "$PY_STATUS" == "venv" ]]; then ok "Python venv detected ($PY_VER)"; else warn "Using system Python ($PY_VER)"; fi
(( ${#py_missing[@]} )) && warn "Missing Python packages: ${py_missing[*]}" || ok "Core Python packages present"

# Permissions / capabilities
if [[ $EUID -ne 0 ]]; then
  warn "Not running as root (some scans require elevated privileges)"
else
  ok "Running with root privileges"
fi

# Interface & subnet
IF=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}') || true
SUBNET=$(ip -o -f inet addr show "$IF" 2>/dev/null | awk '{print $4}' | head -n1) || true
if [[ -n "${IF:-}" && -n "${SUBNET:-}" ]]; then
  ok "Detected interface $IF ($SUBNET)"
else
  warn "Interface / subnet detection failed"
fi

# Writeability tests
OUT_BASE="$REPO_ROOT/output/doctor_check"
mkdir -p "$OUT_BASE" 2>/dev/null || true
if touch "$OUT_BASE/test_$$.tmp" 2>/dev/null; then
  rm -f "$OUT_BASE/test_$$.tmp" 2>/dev/null || true
  ok "Output directory writable: $OUT_BASE"
else
  err "Output directory not writable: $OUT_BASE"
fi

# Wordlist / data presence
WORDLIST_STATUS=()
[[ -s "$REPO_ROOT/passwords.txt" ]] && WORDLIST_STATUS+=(passwords) || warn "passwords.txt missing or empty"
[[ -s "$REPO_ROOT/usernames.txt" ]] && WORDLIST_STATUS+=(usernames) || warn "usernames.txt missing or empty"
[[ -s "$REPO_ROOT/rtsp_paths.csv" ]] && WORDLIST_STATUS+=(rtsp_paths) || warn "rtsp_paths.csv missing"
[[ ${#WORDLIST_STATUS[@]} -eq 3 ]] && ok "All data wordlists present"

# Running processes that may conflict / assist
conflict=()
for p in vlc motion zoneminder; do pgrep -x "$p" >/dev/null 2>&1 && conflict+=("$p"); done
(( ${#conflict[@]} )) && warn "Potential conflicting video services running: ${conflict[*]}" || ok "No conflicting camera services detected"

# JSON summary (emit to stdout after human section if requested)
if [[ "${DOCTOR_JSON:-0}" == "1" || "$*" == *"--json"* ]]; then
  JSON_OUT=$(mktemp)
  cat > "$JSON_OUT" <<JSON
{
  "version": "${VERSION}",
  "timestamp": "${START_TS}",
  "required_missing": [$(printf '"%s",' "${missing_req[@]}" | sed 's/,$//')],
  "recommended_missing": [$(printf '"%s",' "${missing_rec[@]}" | sed 's/,$//')],
  "python_env": "${PY_STATUS}",
  "python_version": "${PY_VER}",
  "python_missing": [$(printf '"%s",' "${py_missing[@]}" | sed 's/,$//')],
  "interface": "${IF:-}",
  "subnet": "${SUBNET:-}",
  "tool_versions": ${tool_versions_json},
  "wordlists_present": [$(printf '"%s",' "${WORDLIST_STATUS[@]}" | sed 's/,$//')],
  "conflicts": [$(printf '"%s",' "${conflict[@]}" | sed 's/,$//')]
}
JSON
  echo
  info "JSON Summary:"; cat "$JSON_OUT"; rm -f "$JSON_OUT"
fi

echo
echo "Diagnostics completed."
exit 0