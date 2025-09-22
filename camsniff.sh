#!/usr/bin/env bash
###############################################################################
# CamSniff 2.0.4 – Camera Reconnaissance & Scanner
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
TARGET_SUBNET="192.168.0.0/24"

usage() {
  cat <<EOF
CamSniff 2.0.4 - Camera Reconnaissance Tool & Scanner
Usage: $0 [OPTIONS]

Options:
  -y, --yes     Skip confirmation prompts
  -q, --quiet   Reduce output verbosity
  -a, --auto    Full automation mode (skip all prompts)
  -t, --target  Specify target subnet (e.g., 192.168.1.0/24)
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
  if (( cidr_part < 8 || cidr_part > 30 )); then
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
  local art=(
"┌───────────────────────────────────────────────────────────────────────────────────────────────┐
|                                     John0n1 Proudly Presents!                                 |
|                                                                                               |
│    ██████╗     █████╗     ███╗   ███╗    ███████╗    ███╗   ██╗    ██╗    ███████╗    ███████╗│
│   ██╔════╝    ██╔══██╗    ████╗ ████║    ██╔════╝    ████╗  ██║    ██║    ██╔════╝    ██╔════╝│
│   ██║         ███████║    ██╔████╔██║    ███████╗    ██╔██╗ ██║    ██║    █████╗      █████╗  │
│   ██║         ██╔══██║    ██║╚██╔╝██║    ╚════██║    ██║╚██╗██║    ██║    ██╔══╝      ██╔══╝  │
│   ╚██████╗    ██║  ██║    ██║ ╚═╝ ██║    ███████║    ██║ ╚████║    ██║    ██║         ██║     │
│    ╚═════╝    ╚═╝  ╚═╝    ╚═╝     ╚═╝    ╚══════╝    ╚═╝  ╚═══╝    ╚═╝    ╚═╝         ╚═╝     │
│                                                                                               │
│                                   ██╗    ██████╗    ██████╗                                   │
│                                  ███║   ██╔═████╗   ╚════██╗                                  │
│                                  ╚██║   ██║██╔██║    █████╔╝                                  │
│                                   ██║   ████╔╝██║    ╚═══██╗                                  │
│                                   ██║██╗╚██████╔╝██╗██████╔╝                                  │
│                                   ╚═╝╚═╝ ╚═════╝ ╚═╝╚═════╝                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
"
 )
  for line in "${art[@]}"; do
    echo "$line"
    sleep "$delay"
  done
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
  CAMERAS_FOUND["$ip:$port"]="$protocol:$url"
  
  # Log structured data
  if [[ -n "${JSON_LOG_FILE:-}" ]]; then
    printf '{"ts":"%s","level":"event","event":"camera_found","ip":"%s","port":%s,"protocol":"%s","url":%s}\n' \
      "$(_ts)" "$ip" "$port" "$protocol" "$(_json_quote "$url")" >> "$JSON_LOG_FILE" 2>/dev/null || true
  fi
}

log_device_info() {
  local ip="$1" info="$2" type="$3"
  log "Device info: $ip - $info (type: $type)"
  
  # Add to device info collection
  DEVICE_INFO["$ip"]="$type:$info"
  
  # Log structured data
  if [[ -n "${JSON_LOG_FILE:-}" ]]; then
    printf '{"ts":"%s","level":"event","event":"device_info","ip":"%s","info":%s,"type":"%s"}\n' \
      "$(_ts)" "$ip" "$(_json_quote "$info")" "$type" >> "$JSON_LOG_FILE" 2>/dev/null || true
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

log_device_info() {
  local ip="$1" info="$2" type="${3:-unknown}"
  if [[ "$QUIET_MODE" -eq 0 ]]; then
    echo -e "${CYAN}[DEVICE INFO] $ip - $info ($type)${RESET}"
  fi
  DEVICE_INFO["$ip"]="$type|$info"
}

# ----------------------------
# Script dir & output dir
# ----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="$SCRIPT_DIR/output/results_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"/{logs,screenshots,reports}
echo "[" > "$OUTPUT_DIR/reports/cameras.json"
JSON_LOG_FILE="$OUTPUT_DIR/logs/scan.jsonl"
# start JSON log file to ensure it's present
: > "$JSON_LOG_FILE"

# collections - used by sourced modules
declare -A STREAMS HOSTS_SCANNED CAMERAS_FOUND DEVICE_INFO
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
  local_path="$SCRIPT_DIR/core/${mod}"
  if [[ -f "$local_path" ]]; then
    log_debug "Sourcing ${mod}"
    # shellcheck source=/dev/null
    source "$local_path"
  else
    log_err "ERROR: Missing file ${mod} in \"$SCRIPT_DIR/core\""
    exit 1
  fi
done

# re-check that we are root for scanning
if (( EUID != 0 )); then
  log_err "ERROR: Must be run as root for scanning operations (sudo)."
  exit 1
fi

# runtime info
if (( QUIET_MODE == 0 )); then
  echo -e "${CYAN}Runtime:${RESET} $(date -Iseconds) | Version: 2.0.4"
fi

# Launch CLI helper if requested (background)
if (( LAUNCH_CLI )); then
  if command -v python3 >/dev/null 2>&1; then
    log "Launching CamSniff Python CLI (camsniff-cli) in background"
    if command -v camsniff-cli >/dev/null 2>&1; then
      start_bg camsniff-cli initdb
    else
      if [[ -f "$SCRIPT_DIR/python_core/cli.py" ]]; then
        start_bg python3 "$SCRIPT_DIR/python_core/cli.py" initdb
      else
        log_warn "CLI not found at python_core/cli.py and camsniff-cli is not installed."
      fi
    fi
  else
    log_warn "Python3 not found; skipping CLI launch"
  fi
fi

# ----------------------------
# RTSP paths load (local or remote fallback)
# ----------------------------
LOCAL_RTSP_FILE="$SCRIPT_DIR/data/rtsp_paths.csv"
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
    if ! tail -n1 "$OUTPUT_DIR/reports/cameras.json" | grep -q '^\]$'; then
      echo "]" >> "$OUTPUT_DIR/reports/cameras.json"
    fi
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
  echo -e "${YELLOW}Tools:${RESET} masscan($(have masscan)) nmap($(have nmap)) ffmpeg($(have ffmpeg)) hydra($(have hydra)) tshark($(have tshark)) avahi-browse($(have avahi-browse))"
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

# tshark: use a safer display filter (if available)
if command -v tshark >/dev/null 2>&1; then
  # Use display filter that attempts to match basic protocols; note: protocol names depend on tshark version
  start_bg tshark -i "$IF" -l -Y "rtsp || http || coap || mqtt || rtmp" -T fields -e ip.src -e tcp.port -e udp.port
else
  log_warn "tshark not available; skipping higher-level protocol sniffing"
fi

# ----------------------------
# Main scanning loop
# ----------------------------
log_debug "Entering main scanning loop"

# Provide a safe sweep wrapper that calls a sweep function from scan_analyze.sh
# If user modules define sweep(), they'll be called. Otherwise a harmless fallback executes.
sweep() {
  if type core_sweep >/dev/null 2>&1; then
    core_sweep "$SUBNET" || true
  elif type sweep_network >/dev/null 2>&1; then
    sweep_network "$SUBNET" || true
  else
    # fallback: quick ping sweep using nmap if available
    if command -v nmap >/dev/null 2>&1; then
      log_debug "Running fallback nmap ping-scan on $SUBNET"
      nmap -sn "$SUBNET" -oG - | awk '/Up$/{print $2}' | while read -r ip; do
        HOSTS_SCANNED["$ip"]=1
        log_debug "Host up: $ip"
      done
    else
      log_debug "No sweep implementation found and nmap missing; sleeping once."
    fi
  fi
}

# optional iot enumeration cycle function should be defined by iot_enumerate.sh
iot_enumeration_cycle() {
  if type iot_enumeration_cycle_impl >/dev/null 2>&1; then
    iot_enumeration_cycle_impl || true
  else
    return 0
  fi
}

# loop forever with adjustable timing
while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep

  if type iot_enumeration_cycle >/dev/null 2>&1; then
    log_debug "Running IoT enumeration cycle"
    iot_enumeration_cycle || true
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
    sleep "${SS:-60}"
  fi
done