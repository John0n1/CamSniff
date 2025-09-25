#!/usr/bin/env bash
###############################################################################
# CamSniff 1.0.4 – Camera Reconnaissance & Scanner
# https://github.com/John0n1/CamSniff
###############################################################################
set -euo pipefail
IFS=$'\n\t'

# ----------------------------
# Defaults / CLI parsing
# ----------------------------
SKIP_PROMPT=0
QUIET_MODE=0
_AUTO_MODE=0
INTERACTIVE_MODE=1   # default enabled when TTY and not quiet/auto; overridable via --no-interactive
DOCTOR_MODE=0
TARGET_SUBNET="192.168.0.0/24"
ONCE_MODE=0
MAX_CYCLES=0    # 0 = unlimited unless ONCE_MODE
DURATION_SEC=0   # 0 = unlimited
CYCLE_COUNT=0
START_EPOCH=$(date +%s)

VERSION_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../VERSION"
CAMSNIFF_VERSION="${CAMSNIFF_VERSION:-$(cat "$VERSION_FILE" 2>/dev/null || echo dev)}"

usage() {
  cat <<EOF
CamSniff ${CAMSNIFF_VERSION} - Camera Reconnaissance Tool & Scanner
Usage: $0 [OPTIONS]

Options:
  -y, --yes     Skip confirmation prompts
  -q, --quiet   Reduce output verbosity
  -a, --auto    Full automation mode (skip all prompts)
  -t, --target  Specify target subnet (e.g., 192.168.1.0/24)
      --once    Run a single sweep cycle then exit
      --cycles N  Run at most N sweep cycles then exit
  --duration 1h|600s|15m  Maximum wall time; stops after exceeded
  --no-interactive  Disable interactive prompts (still logs phases)
  -d, --doctor  Run environment diagnostics and exit
  -h, --help    Show this help message

Examples:
  sudo $0 -a                    # Full automatic scan
  sudo $0 -t 192.168.1.0/24     # Scan specific subnet
  sudo $0 -y -q                 # Skip prompts, quiet mode
EOF
}

# Input validation functions
validate_subnet() {
  local subnet="$1"
  # Basic CIDR notation validation
  if [[ ! "$subnet" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    return 1
  fi
  
  # Validate IP parts
  IFS='/' read -r ip_part cidr_part <<< "$subnet"
  IFS='.' read -ra ip_octets <<< "$ip_part"
  
  for octet in "${ip_octets[@]}"; do
    if (( octet < 0 || octet > 255 )); then
      return 1
    fi
  done
  
  # Validate CIDR
  if (( cidr_part < 0 || cidr_part > 32 )); then
    return 1
  fi
  
  return 0
}

sanitize_input() {
  # Remove potentially dangerous characters
  echo "$1" | sed 's/[;&|`$(){}]//' | head -c 100
}

# Simple parse to keep compatibility with how user already calls the script
while [[ $# -gt 0 ]]; do
  case $1 in
    -y|--yes) SKIP_PROMPT=1; shift ;;
    -q|--quiet) QUIET_MODE=1; shift ;;
    -a|--auto) _AUTO_MODE=1; SKIP_PROMPT=1; shift ;;
    -t|--target) 
      if [[ -z "$2" ]]; then
        echo "Error: --target requires a subnet argument" >&2
        exit 1
      fi
      TARGET_SUBNET="$(sanitize_input "$2")"
      if ! validate_subnet "$TARGET_SUBNET"; then
        echo "Error: Invalid subnet format: $TARGET_SUBNET" >&2
        echo "Expected format: 192.168.1.0/24" >&2
        exit 1
      fi
      shift 2 ;;
    --once) ONCE_MODE=1; MAX_CYCLES=1; shift ;;
    --cycles)
      if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ || "$2" -le 0 ]]; then
        echo "Error: --cycles requires positive integer" >&2; exit 1; fi
      MAX_CYCLES="$2"; shift 2 ;;
    --duration)
      if [[ -z "${2:-}" ]]; then echo "Error: --duration requires value (e.g. 600s, 10m, 1h)" >&2; exit 1; fi
      DUR_RAW="$2"; shift 2
      if [[ "$DUR_RAW" =~ ^([0-9]+)([smh]?)$ ]]; then
        num="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
        case "$unit" in
          s|"" ) DURATION_SEC=$num ;;
          m) DURATION_SEC=$((num*60)) ;;
          h) DURATION_SEC=$((num*3600)) ;;
          *) echo "Error: invalid duration unit (use s/m/h)" >&2; exit 1 ;;
        esac
      else
        echo "Error: invalid duration format: $DUR_RAW" >&2; exit 1
      fi ;;
    --no-interactive)
      INTERACTIVE_MODE=0; shift ;;
  -d|--doctor) DOCTOR_MODE=1; shift ;;
  -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; echo "Use --help for usage information" >&2; exit 1 ;;
  esac
done

# ----------------------------
# Colors (only used if output is a tty)
# ----------------------------
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; RESET=''
fi

# ----------------------------
# Animation / banner helpers
# ----------------------------
animate_text_from_side() {
  local text="$1"
  local delay="${2:-0.05}"
  if [[ ! -t 1 || "${NO_ANIM:-0}" == "1" || "$QUIET_MODE" -eq 1 ]]; then
    printf "%s\n" "$text"
    return 0
  fi
  local width
  width=$(tput cols 2>/dev/null || echo 80)
  local padding=$((width - ${#text}))
  (( padding < 0 )) && padding=0
  for ((i=padding; i>=0; i--)); do
    printf "\r%*s%s" "$i" "" "$text"
    sleep "$delay"
  done
  echo
}

rain_ascii_art() {
  local delay="${1:-0.03}"
  if [[ ! -t 1 || "${NO_ANIM:-0}" == "1" || "$QUIET_MODE" -eq 1 ]]; then
    printf "CamSniff by John0n1\n"
    return 0
  fi
  # ASCII art (requested) animated line-by-line like rain
  # To disable: export NO_ANIM=1 or run with --quiet
  local art_content
  art_content=$(cat <<'EOF'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀CamSniff 1.0.4⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣸⣏⠛⠻⠿⣿⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣷⣦⣤⣈⠙⠛⠿⣿⣷⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⣈⠙⠻⠿⣿⣷⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⡉⠛⠻⢿⣿⣷⣶⣤⣀⠀⠀
⠀⠀⠀⠉⠙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⢻⣍⡉⠉⣿⠇⠀
⠀⠀⠀⠀⠀⠀⠀⢹⡏⢹⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⣰⣿⣿⣾⠏⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣿⠈⣿⠸⣯⠉⠛⠿⢿⣿⣿⣿⣿⡏⠀⠻⠿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢿⡆⢻⡄⣿⡀⠀⠀⠀⠈⠙⠛⠿⠿⠿⠿⠛⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠘⣇⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣀⣿⣴⣿⢾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣴⡶⠾⠟⠛⠋⢹⡏⠀⢹⡇⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣿⠀⠀⠀⠀⢀⣈⣿⣶⠿⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⣿⣴⠶⠞⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠁⠀⠀⠀ You think you're alone, but what if someone’s eyes are fixed on you right now?
        The air feels heavy, doesn’t it? Like someone’s silently observing you, waiting.⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
EOF
  )
  # Print with a subtle leading blank lines to mimic a gentle rain fall-in effect
  while IFS= read -r line; do
    echo "$line"
    sleep "$delay"
  done <<< "$art_content"
}

# ----------------------------
# Enhanced Logging System (respects QUIET_MODE and LOG_LEVEL)
# ----------------------------
LOG_LEVEL="${LOG_LEVEL:-INFO}"  # DEBUG, INFO, WARN, ERROR

_json_quote() {
  # returns a JSON string quoted value for arbitrary input
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$(printf '%s' "$*")"
import json, sys
print(json.dumps(sys.argv[1]))
PY
  else
    # conservative fallback: escape backslash and quotes, wrap in quotes
    local s
    s=$(printf '%s' "$*" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;s/\n/\\n/;ta')
    printf '"%s"' "$s"
  fi
}

_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_should_log() {
  local level="$1"
  case "$LOG_LEVEL" in
    DEBUG) return 0 ;;
    INFO) [[ "$level" != "DEBUG" ]] && return 0 ;;
    WARN) [[ "$level" =~ ^(WARN|ERROR)$ ]] && return 0 ;;
    ERROR) [[ "$level" == "ERROR" ]] && return 0 ;;
  esac
  return 1
}

_log_to_file() {
  local level="$1" message="$2"
  if [[ -n "${JSON_LOG_FILE:-}" ]]; then
    printf '{"ts":"%s","level":"%s","msg":%s}\n' "$(_ts)" "$level" "$(_json_quote "$message")" >> "$JSON_LOG_FILE" 2>/dev/null || true
  fi
}

log() {
  local level="INFO"
  _should_log "$level" || return 0
  
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${GREEN}[+] $*${RESET}"
  fi
  _log_to_file "$level" "$*"
}

log_debug() {
  local level="DEBUG"
  _should_log "$level" || return 0
  
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${CYAN}[DEBUG] $*${RESET}"
  fi
  _log_to_file "$level" "$*"
}

log_warn() {
  local level="WARN"
  _should_log "$level" || return 0
  
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${YELLOW}[WARN] $*${RESET}"
  fi
  _log_to_file "$level" "$*"
}

log_err() {
  local level="ERROR"
  _should_log "$level" || return 0
  
  echo -e "${RED}[ERROR] $*${RESET}" >&2
  _log_to_file "$level" "$*"
}

log_camera_found() {
  local ip="$1" port="$2" protocol="$3" url="$4"
  log "Camera found: $ip:$port ($protocol) - $url"
  
  # Add to cameras collection
  if declare -p CAMERAS_FOUND >/dev/null 2>&1; then
    CAMERAS_FOUND["$ip:$port"]="$protocol:$url"
  fi
  
  # Log structured data
  if [[ -n "${JSON_LOG_FILE:-}" ]]; then
    printf '{"ts":"%s","level":"event","event":"camera_found","ip":"%s","port":%s,"protocol":"%s","url":%s}\n' \
      "$(_ts)" "$ip" "$port" "$protocol" "$(_json_quote "$url")" >> "$JSON_LOG_FILE" 2>/dev/null || true
  fi

  # Interactive prompt hook (implemented in later patch step)
  if (( INTERACTIVE_MODE == 1 )); then
    if type interactive_camera_prompt >/dev/null 2>&1; then
      interactive_camera_prompt "$ip" "$port" "$protocol" "$url" || true
    fi
  fi
}

log_device_info() {
  local ip="$1" info="$2" type="${3:-unknown}"
  # Store consistently as type|info
  DEVICE_INFO["$ip"]="$type|$info"
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${CYAN}[DEVICE INFO] $ip - $info ($type)${RESET}"
  fi
  if [[ -n "${JSON_LOG_FILE:-}" ]]; then
    printf '{"ts":"%s","level":"event","event":"device_info","ip":"%s","type":"%s","info":%s}\n' \
      "$(_ts)" "$ip" "$type" "$(_json_quote "$info")" >> "$JSON_LOG_FILE" 2>/dev/null || true
  fi
}

log_camera_found_legacy() {
  local ip="$1" port="$2" protocol="$3" url="$4" creds="${5:-}" ts
  ts="$(date -Iseconds)"
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${GREEN}[CAMERA FOUND] $ip:$port ($protocol) - $url${RESET}"
  fi
  # write a camera object as a JSON line (will be converted to array on finalize)
  printf '%s\n' \
    "{\"timestamp\":$( _json_quote "$ts" ),\"ip\":$( _json_quote "$ip" ),\"port\":$( _json_quote "$port" ),\"protocol\":$( _json_quote "$protocol" ),\"url\":$( _json_quote "$url" ),\"credentials\":$( _json_quote "$creds" ),\"status\":\"active\"}," \
    >> "$OUTPUT_DIR/reports/cameras.json" 2>/dev/null || true

  CAMERAS_FOUND["$ip:$port"]="$protocol|$url|$creds"

  printf '{"type":"camera_found","timestamp":%s,"ip":%s,"port":%s,"protocol":%s,"url":%s}\n' \
    "$(_json_quote "$ts")" "$(_json_quote "$ip")" "$(_json_quote "$port")" "$(_json_quote "$protocol")" "$(_json_quote "$url")" >> "$JSON_LOG_FILE" 2>/dev/null || true
}

## (Removed duplicate log_device_info definition)

# ----------------------------
# Script dir & output dir
# ----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Detect packaged layout (/usr/lib/camsniff/src) or legacy (/usr/lib/camsniff)
if [[ "$SCRIPT_DIR" == /usr/lib/camsniff/src* || "$SCRIPT_DIR" == /usr/lib/camsniff ]]; then
  INSTALL_MODE=1
else
  INSTALL_MODE=0
fi
export INSTALL_MODE

export REPO_ROOT="$SCRIPT_DIR"
export PY_CORE_DIR="$SCRIPT_DIR/python_core"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
if (( INSTALL_MODE )); then
  OUTPUT_BASE="/var/lib/camsniff"
  mkdir -p "$OUTPUT_BASE" 2>/dev/null || true
  OUTPUT_DIR="$OUTPUT_BASE/results_$TIMESTAMP"
else
  OUTPUT_DIR="$SCRIPT_DIR/output/results_$TIMESTAMP"
fi
mkdir -p "$OUTPUT_DIR"/{logs,screenshots,reports}
echo "[" > "$OUTPUT_DIR/reports/cameras.json"
JSON_LOG_FILE="$OUTPUT_DIR/logs/scan.jsonl"
# start JSON log file to ensure it's present
: > "$JSON_LOG_FILE"

# collections - used by sourced modules (defensive; don't clobber if already declared by earlier sourcing)
declare -p STREAMS        >/dev/null 2>&1 || declare -A STREAMS
declare -p HOSTS_SCANNED  >/dev/null 2>&1 || declare -A HOSTS_SCANNED
declare -p CAMERAS_FOUND  >/dev/null 2>&1 || declare -A CAMERAS_FOUND
declare -p DEVICE_INFO    >/dev/null 2>&1 || declare -A DEVICE_INFO
declare -a BG_PIDS
export STREAMS HOSTS_SCANNED CAMERAS_FOUND DEVICE_INFO BG_PIDS

# Helper to track background PIDs for graceful shutdown
start_bg() {
  # usage: start_bg command args...
  "$@" >/dev/null 2>&1 &
  BG_PIDS+=("$!")
}

# ----------------------------
# CLI / prompt
# ----------------------------
if (( ! QUIET_MODE )); then
  if [[ -t 1 ]]; then clear; fi

  printf "%sCamSniff is a powerful tool designed to:%s\n" "$CYAN" "$RESET"
  printf "%s- Discover, analyze and display network-connected cameras%s\n" "$GREEN" "$RESET"
  printf "%s- Perform RTSP, HTTP, CoAP, RTMP, MQTT and more%s\n" "$GREEN" "$RESET"
  printf "%s- Identify vulnerabilities and test common credentials%s\n" "$GREEN" "$RESET"
  printf "%s- Generate AI-based insights from camera streams%s\n" "$GREEN" "$RESET"
  echo
  sleep 0.2
  rain_ascii_art 0.08


  echo
  printf "%sThis will happen next:%s\n" "$YELLOW" "$RESET"
  printf "%s1.%s Dependencies will be checked and installed if missing.\n" "$CYAN" "$RESET"
  printf "%s2.%s Network scanning will begin to identify active devices.\n" "$CYAN" "$RESET"
  printf "%s3.%s Camera streams will be analyzed and displayed.\n" "$CYAN" "$RESET"
  printf "%s4.%s Results will be saved to structured output directory.\n" "$CYAN" "$RESET"
  printf "%s5.%s You can choose to start the scan or exit at any time.\n" "$CYAN" "$RESET"
  printf "%sPress 'Y' to start, 'K' to start + CLI, or 'N' to exit.%s\n" "$YELLOW" "$RESET"
fi

LAUNCH_CLI=0
if (( SKIP_PROMPT == 0 )); then
  while true; do
    read -rp "$(echo -e "${CYAN}Start CamSniff? (Y/N/K): ${RESET}")" yn
    case $yn in
      [Yy]*) break ;;
      [Kk]*) LAUNCH_CLI=1; break ;;
      [Nn]*) echo -e "${RED}Exiting. Sniff will miss you. 😢 Goodbye!${RESET}"; exit 0 ;;
      *) echo -e "${YELLOW}Please press 'Y' to start, 'K' to start + CLI, or 'N' to exit.${RESET}" ;;
    esac
  done
else
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${GREEN}Auto-mode enabled, starting scan...${RESET}"
  fi
fi

# Finalize interactive mode decision (TTY required, disabled if quiet or auto flags)
if (( QUIET_MODE == 1 || _AUTO_MODE == 1 )); then
  INTERACTIVE_MODE=0
fi
if [[ ! -t 1 ]]; then
  INTERACTIVE_MODE=0
fi
export INTERACTIVE_MODE

# Doctor mode: run diagnostics and exit
if (( DOCTOR_MODE == 1 )); then
  if [[ -f "$SCRIPT_DIR/scripts/doctor.sh" ]]; then
    echo -e "${CYAN}[Doctor] Running diagnostics...${RESET}"
    bash "$SCRIPT_DIR/scripts/doctor.sh" || true
  elif [[ -f "$SCRIPT_DIR/core/doctor.sh" ]]; then
    echo -e "${CYAN}[Doctor] Running diagnostics (core)...${RESET}"
    bash "$SCRIPT_DIR/core/doctor.sh" || true
  else
    echo -e "${YELLOW}[Doctor] No doctor.sh script found.${RESET}"
  fi
  exit 0
fi

# ----------------------------
# Dependency/install handling (first run)
# ----------------------------
DEPS_INSTALLED_FILE="$SCRIPT_DIR/.deps_installed"
if [[ ! -f "$DEPS_INSTALLED_FILE" ]]; then
  if (( EUID != 0 )); then
    log_err "ERROR: First run must be with sudo to install dependencies."
    exit 1
  fi
  if [[ -f "$SCRIPT_DIR/core/install_deps.sh" && -x "$SCRIPT_DIR/core/install_deps.sh" ]]; then
    log "Installing dependencies (first run)... this can take a while"
    # run installer (don't source) so it's a separate environment and safe
    bash "$SCRIPT_DIR/core/install_deps.sh"
    touch "$DEPS_INSTALLED_FILE"
  elif [[ -f "$SCRIPT_DIR/core/install_deps.sh" ]]; then
    log "Installing dependencies (first run)... this can take a while"
    bash "$SCRIPT_DIR/core/install_deps.sh"
    touch "$DEPS_INSTALLED_FILE"
  elif [[ -f "$SCRIPT_DIR/scripts/install_deps.sh" ]]; then
    log "Installing dependencies (first run)... this can take a while"
    bash "$SCRIPT_DIR/scripts/install_deps.sh"
    touch "$DEPS_INSTALLED_FILE"
  else
    log_warn "No install_deps.sh found; assuming dependencies are present."
    touch "$DEPS_INSTALLED_FILE"
  fi
fi

# ----------------------------
# Source submodules (required)
# ----------------------------
# Fail fast if missing — those modules implement the scanning logic
for mod in setup.sh env_setup.sh install_deps.sh scan_analyze.sh cleanup.sh iot_enumerate.sh; do
  if [[ -f "$SCRIPT_DIR/core/${mod}" ]]; then
    log_debug "Sourcing ${mod} (core/)"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/core/${mod}"
  elif [[ -f "$SCRIPT_DIR/scripts/${mod}" ]]; then
    log_debug "Sourcing ${mod} (scripts/)"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/scripts/${mod}"
  else
    log_err "ERROR: Missing file ${mod} (searched in core/ and scripts/)"
    exit 1
  fi
done

# Optional diagnostic to confirm which sweep functions are present (set SWEEP_DIAG=1 to always print)
diagnose_sweep() {
  local have_core have_network
  if type core_sweep >/dev/null 2>&1; then have_core=1; else have_core=0; fi
  if type sweep_network >/dev/null 2>&1; then have_network=1; else have_network=0; fi
  if [[ "${SWEEP_DIAG:-0}" == 1 || ( "$have_core" -eq 0 && "$have_network" -eq 0 ) ]]; then
    # Use log_warn so it's visible if not found; quiet mode will still suppress unless missing both
    if (( have_core )); then
      log_debug "Detected sweep function: core_sweep"
    fi
    if (( have_network )); then
      log_debug "Detected sweep function: sweep_network"
    fi
    if (( !have_core && !have_network )); then
      log_warn "No advanced sweep functions found (core_sweep / sweep_network). Fallback nmap ping-scan will be used."
    fi
  fi
}
diagnose_sweep

# re-check that we are root for scanning
if (( EUID != 0 )); then
  log_err "ERROR: Must be run as root for scanning operations (sudo)."
  exit 1
fi

# runtime info
if (( QUIET_MODE == 0 )); then
  echo -e "${CYAN}Runtime:${RESET} $(date -Iseconds) | Version: ${CAMSNIFF_VERSION}"
fi

# Launch CLI helper if requested (background)
if (( LAUNCH_CLI )); then
  if command -v python3 >/dev/null 2>&1; then
    log "Launching CamSniff Python CLI (camsniff-cli) in background"
    if command -v camsniff-cli >/dev/null 2>&1; then
      start_bg camsniff-cli initdb
    else
      if [[ -f "$PY_CORE_DIR/cli.py" ]]; then
        start_bg python3 "$PY_CORE_DIR/cli.py" initdb
      else
        log_warn "CLI not found at $PY_CORE_DIR/cli.py and camsniff-cli is not installed."
      fi
    fi
  else
    log_warn "Python3 not found; skipping CLI launch"
  fi
fi

# ----------------------------
# RTSP paths load (local or remote fallback)
# ----------------------------
LOCAL_RTSP_FILE="$SCRIPT_DIR/rtsp_paths.csv"
RTSP_SOURCE=""
if [[ -s "$LOCAL_RTSP_FILE" ]]; then
  RTSP_SOURCE="$LOCAL_RTSP_FILE"
else
  if [[ -n "${RTSP_LIST_URL:-}" ]]; then
    TMP_RTSP="$(mktemp)"
    if curl -sfL "$RTSP_LIST_URL" -o "$TMP_RTSP"; then
      RTSP_SOURCE="$TMP_RTSP"
    else
      rm -f "$TMP_RTSP"
    fi
  fi
fi

if [[ -n "$RTSP_SOURCE" ]]; then
  # prefer header with rtsp_url column
  mapfile -t RTSP_PATHS < <(
    awk -F',' '
      NR==1 {
        for (i=1;i<=NF;i++) if ($i ~ /^rtsp_url$/) col=i;
        next
      }
      NR>1 && col>0 {
        gsub(/^[ \t"]+|[ \t"]+$/, "", $col);
        if ($col ~ /^rtsp:\/\//) print $col
      }
    ' "$RTSP_SOURCE" | tr -d '"' | sort -u
  )

  if (( ${#RTSP_PATHS[@]} == 0 )); then
    # fallback: any field with rtsp://
    mapfile -t RTSP_PATHS < <(awk -F',' '{for(i=1;i<=NF;i++) if($i ~ /rtsp:\/\//) print $i}' "$RTSP_SOURCE" | tr -d '"' | sort -u)
  fi
else
  log_warn "No RTSP path list available; using minimal built-in list"
  RTSP_PATHS=(
    "rtsp://{{ip_address}}:{{port}}/video"
    "rtsp://{{ip_address}}:{{port}}/cam"
    "rtsp://{{ip_address}}:{{port}}/live"
  )
fi

if (( QUIET_MODE == 0 )); then
  echo -e "${CYAN}RTSP Source:${RESET} ${RTSP_SOURCE:-built-in}"
  echo -e "${CYAN}Web UI:${RESET} run ./webui.sh (default http://localhost:8088)"
fi

# ----------------------------
# Finalize reports on exit
# ----------------------------
finalize_reports() {
  # remove trailing comma from cameras.json lines and wrap as array
  if [[ -f "$OUTPUT_DIR/reports/cameras.json" ]]; then
    # if file is not empty, convert to proper JSON array
    sed -i '$ s/,$//' "$OUTPUT_DIR/reports/cameras.json" 2>/dev/null || true
    # ensure closing bracket if not present
    if ! tail -n1 "$OUTPUT_DIR/reports/cameras.json" | grep -q '^]$'; then
      echo "]" >> "$OUTPUT_DIR/reports/cameras.json"
    fi
  fi

  # Run shared cleanup routine if defined (cleanup.sh when sourced)
  if type cleanup >/dev/null 2>&1; then
    cleanup || true
  fi

  # kill background pids
  if (( ${#BG_PIDS[@]} > 0 )); then
    log_debug "Killing background PIDs: ${BG_PIDS[*]}"
    for pid in "${BG_PIDS[@]}"; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" >/dev/null 2>&1 || true
      fi
    done
  fi

  log "Final reports saved to: $OUTPUT_DIR"
}

trap finalize_reports EXIT INT TERM

# ----------------------------
# Interface & subnet detection
# ----------------------------
detect_interface() {
  local ifname
  ifname="$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')"
  if [[ -z "$ifname" ]]; then
    # fallback: first non-loopback with an ipv4 addr
    ifname="$(ip -o -4 addr show up primary scope global | awk '{print $2; exit}')"
  fi
  echo "$ifname"
}

IF="${IF:-$(detect_interface)}"
if [[ -z "$IF" ]]; then
  log_err "ERROR: Could not detect network interface. Please set --target or fix networking."
  exit 1
fi

# Prefer explicit target if provided
if [[ -n "$TARGET_SUBNET" ]]; then
  SUBNET="$TARGET_SUBNET"
else
  SUBNET=$(ip -o -f inet addr show "$IF" | awk '{print $4}' | head -n1 || true)
fi

if [[ -z "$SUBNET" ]]; then
  log_err "ERROR: Could not detect subnet. Provide with -t/--target."
  exit 1
fi

log "Interface: $IF"
log "Subnet: $SUBNET"

# ----------------------------
# Feature flags summary
# ----------------------------
flag_str(){
  local v="$1"; if [[ "$v" == "1" ]]; then echo -e "${GREEN}ON${RESET}"; else echo -e "${RED}OFF${RESET}"; fi
}

if (( QUIET_MODE == 0 )); then
  echo -e "${YELLOW}Config Summary:${RESET}"
  echo -e "  Output Dir : $OUTPUT_DIR"
  echo -e "  IoT Enum   : $(flag_str "${ENABLE_IOT_ENUMERATION:-0}")"
  echo -e "  PCAP Cap   : $(flag_str "${ENABLE_PCAP_CAPTURE:-0}")"
  echo -e "  WiFi Scan  : $(flag_str "${ENABLE_WIFI_SCAN:-0}")"
  echo -e "  BLE Scan   : $(flag_str "${ENABLE_BLE_SCAN:-0}")"
  echo -e "  Zigbee/Z-W : $(flag_str "${ENABLE_ZIGBEE_ZWAVE_SCAN:-0}")"
  echo -e "  Stealth    : $(flag_str "${STEALTH_MODE:-0}")"
  echo -e "  Nmap Vuln  : $(flag_str "${ENABLE_NMAP_VULN:-0}")"
  echo -e "  Bruteforce : $(flag_str "${ENABLE_BRUTE_FORCE:-0}")"
  have(){ command -v "$1" &>/dev/null && echo yes || echo no; }
  echo -e "${YELLOW}Tools:${RESET} masscan($(have masscan)) nmap($(have nmap)) ffmpeg($(have ffmpeg)) hydra($(have hydra)) tshark($(have tshark)) avahi-browse($(have avahi-browse)) coap-client($(have coap-client)) rtmpdump($(have rtmpdump)) mosquitto_sub($(have mosquitto_sub)) gobuster($(have gobuster))"
fi

# ----------------------------
# Start lightweight sniffers and track pids
# ----------------------------
# Note: capture processes are started with start_bg so we can kill them gracefully.
# tcpdump: ARP and DHCP only
if command -v tcpdump >/dev/null 2>&1; then
  start_bg tcpdump -i "$IF" -l -n -q '(arp or (udp port 67 or udp port 68))'
  start_bg tcpdump -i "$IF" -l -n -q '(udp port 5353 or udp port 3702)'
else
  log_warn "tcpdump not available; skipping arp/dhcp/mDNS sniffers"
fi

if command -v tshark >/dev/null 2>&1; then

  start_bg tshark -i "$IF" -l -Y "rtsp || http || coap || mqtt || rtmp" -T fields -e ip.src -e tcp.port -e udp.port
else
  log_warn "tshark not available; skipping higher-level protocol sniffing"
fi

# ----------------------------
# Main scanning loop
# ----------------------------
log_debug "Entering main scanning loop"
if (( ONCE_MODE )); then log_debug "ONCE_MODE enabled"; fi
if (( MAX_CYCLES>0 && !ONCE_MODE )); then log_debug "Max cycles: $MAX_CYCLES"; fi
if (( DURATION_SEC>0 )); then log_debug "Max duration (sec): $DURATION_SEC"; fi
sweep() {
  if type core_sweep >/dev/null 2>&1; then
    log_debug "Using core_sweep implementation"
    core_sweep "$SUBNET" || true
  elif type sweep_network >/dev/null 2>&1; then
    log_debug "Using sweep_network implementation"
    sweep_network "$SUBNET" || true
  else
    # fallback: quick ping sweep using nmap if available
    if command -v nmap >/dev/null 2>&1; then
      log_warn "Advanced sweep functions not found (core_sweep/sweep_network). Using fallback nmap ping-scan only."
      log_debug "Running fallback nmap ping-scan on $SUBNET"
      nmap -sn "$SUBNET" -oG - | awk '/Up$/{print $2}' | while read -r ip; do
        HOSTS_SCANNED["$ip"]=1
        log_debug "Host up: $ip"
      done
    else
      log_warn "No sweep implementation and nmap not installed. Cannot enumerate hosts this cycle."
    fi
  fi
}

iot_enumeration_cycle() {
  if type iot_enumeration_cycle_impl >/dev/null 2>&1; then
    iot_enumeration_cycle_impl || true
  else
    return 0
  fi
}

# loop (bounded if user specified constraints)
while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep
  ((CYCLE_COUNT++))

  if type iot_enumeration_cycle >/dev/null 2>&1; then
    log_debug "Running IoT enumeration cycle"
    iot_enumeration_cycle || true
  fi

  # Break conditions
  NOW=$(date +%s)
  if (( ONCE_MODE )); then
    log "Single cycle complete (--once). Exiting."
    break
  fi
  if (( MAX_CYCLES>0 && CYCLE_COUNT>=MAX_CYCLES )); then
    log "Reached max cycles ($MAX_CYCLES). Exiting."
    break
  fi
  if (( DURATION_SEC>0 && (NOW - START_EPOCH) >= DURATION_SEC )); then
    log "Reached max duration (${DURATION_SEC}s). Exiting."
    break
  fi

  if [[ "${STEALTH_MODE:-0}" -eq 1 ]]; then
    base=${SS:-60}
    jitter=$((RANDOM % 11 - 5))
    next=$((base + jitter))
    (( next<5 )) && next=5
    log "Stealth sleep ${next}s (base ${base}s, jitter ${jitter}s)"
    sleep "$next"
  else
    log "Sleeping ${SS:-60}s..."
    # Adjust sleep if duration boundary would be exceeded
    if (( DURATION_SEC>0 )); then
      REM=$(( START_EPOCH + DURATION_SEC - NOW ))
      if (( REM <= 0 )); then
        log "Duration boundary reached mid-loop. Exiting without extra sleep."
        break
      fi
      SLEEP_SECS=${SS:-60}
      if (( SLEEP_SECS > REM )); then SLEEP_SECS=$REM; fi
      sleep "$SLEEP_SECS"
    else
      sleep "${SS:-60}"
    fi
  fi
done

# Print concise final summary to console (non-infinite modes)
if (( ONCE_MODE || MAX_CYCLES>0 || DURATION_SEC>0 )); then
  SUMMARY_TXT=$(ls -1t "$OUTPUT_DIR"/reports/summary_*.txt 2>/dev/null | head -n1 || true)
  if [[ -f "$SUMMARY_TXT" ]]; then
    echo "--- Final Summary (truncated) ---"
    sed -n '1,40p' "$SUMMARY_TXT"
    echo "(Full report: $SUMMARY_TXT)"
  else
    echo "No summary report generated."
  fi
fi
