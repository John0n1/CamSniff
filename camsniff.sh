#!/usr/bin/env bash
###############################################################################
# CamSniff 1.0.3 – Camera Reconnaissance & Scanner
# https://github.com/John0n1/CamSniff
###############################################################################
set -euo pipefail
IFS=$'\n\t'

# Command line options parsing
SKIP_PROMPT=0
QUIET_MODE=0
_AUTO_MODE=0
TARGET_SUBNET=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -y|--yes) SKIP_PROMPT=1; shift ;;
    -q|--quiet) QUIET_MODE=1; shift ;;
  -a|--auto) _AUTO_MODE=1; SKIP_PROMPT=1; shift ;;
    -t|--target) TARGET_SUBNET="$2"; shift 2 ;;
    -h|--help)
  echo "CamSniff 1.0.3 - Camera Reconnaissance Tool & Scanner"
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -y, --yes     Skip confirmation prompts"
      echo "  -q, --quiet   Reduce output verbosity"
      echo "  -a, --auto    Full automation mode (skip all prompts)"
      echo "  -t, --target  Specify target subnet (e.g., 192.168.1.0/24)"
      echo "  -h, --help    Show this help message"
      echo ""
      echo "Examples:"
      echo "  sudo $0 -a                    # Full automatic scan"
      echo "  sudo $0 -t 192.168.1.0/24    # Scan specific subnet"
      echo "  sudo $0 -y -q                # Skip prompts, quiet mode"
      exit 0
      ;;
    *) echo "Unknown option: $1"; echo "Use --help for usage information"; exit 1 ;;
  esac
done

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

# Animation functions
animate_text_from_side() {
  local text="$1"
  local delay="${2:-0.05}"
  if [[ ! -t 1 || "${NO_ANIM:-0}" == "1" ]]; then
    printf "%s\n" "$text"
    return 0
  fi
  local width
  width=$(tput cols 2>/dev/null || echo 80)
  local padding=$((width - ${#text}))
  (( padding < 0 )) && padding=0

  for ((i=padding; i>=0; i--)); do
    printf "\r%*s%s" $i "" "$text"
    sleep "$delay"
  done
  echo
}

rain_ascii_art() {
  local delay="${1:-0.03}"
  if [[ ! -t 1 || "${NO_ANIM:-0}" == "1" ]]; then
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

# Display banner with animations
if (( !QUIET_MODE )); then
  [[ -t 1 ]] && clear || true

  printf "%sCamSniff is a powerful tool designed to:%s\n" "$CYAN" "$RESET"
  printf "%s- Discover, analyze and display network-connected cameras%s\n" "$GREEN" "$RESET"
  printf "%s- Perform RTSP, HTTP, CoAP, RTMP, MQTT and more%s\n" "$GREEN" "$RESET"
  printf "%s- Identify vulnerabilities and test common credentials%s\n" "$GREEN" "$RESET"
  printf "%s- Generate AI-based insights from camera streams%s\n" "$GREEN" "$RESET"

  echo
  sleep 0.5

  rain_ascii_art 0.2

  echo
  printf "%sThis will happen next:%s\n" "$YELLOW" "$RESET"
  printf "%s1.%s Dependencies will be checked and installed if missing.\n" "$CYAN" "$RESET"
  printf "%s2.%s Network scanning will begin to identify active devices.\n" "$CYAN" "$RESET"
  printf "%s3.%s Camera streams will be analyzed and displayed.\n" "$CYAN" "$RESET"
  printf "%s4.%s Results will be saved to structured output directory.\n" "$CYAN" "$RESET"
  printf "%s5.%s You can choose to start the scan or exit at any time.\n" "$CYAN" "$RESET"
  printf "%sPress 'Y' to start, 'K' to start + CLI, or 'N' to exit.%s\n" "$YELLOW" "$RESET"
fi

# Confirmation prompt
LAUNCH_CLI=0
if (( !SKIP_PROMPT )); then
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
  echo -e "${GREEN}Auto-mode enabled, starting scan...${RESET}"
fi


# Get directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Base working data directory
DATADIR="$SCRIPT_DIR"

# Output directory now relative to script dir
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="$SCRIPT_DIR/output/results_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"/{logs,screenshots,reports}

# Helper to colorize ON/OFF
flag_str(){
  local v="$1"; if [[ "$v" == "1" ]]; then echo -e "${GREEN}ON${RESET}"; else echo -e "${RED}OFF${RESET}"; fi
}

# Python venv path
VENV="$SCRIPT_DIR/.camvenv"

# Structured JSON log file (append-only)
JSON_LOG_FILE="$OUTPUT_DIR/logs/scan.jsonl"

# Logging and output
declare -A STREAMS HOSTS_SCANNED CAMERAS_FOUND DEVICE_INFO
echo "[" > "$OUTPUT_DIR/reports/cameras.json"

_ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_json_quote(){
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' 2>/dev/null "$@"
import json,sys
print(json.dumps(" ".join(sys.argv[1:])))
PY
  else
    # Minimal shell fallback: escape backslashes and quotes
    local s
    s=$(printf '%s' "$*" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    printf '"%s"' "$s"
  fi
}

log()       { echo -e "${GREEN}[+] $*${RESET}"; printf '{"ts":"%s","level":"info","msg":%s}\n' "$(_ts)" "$(_json_quote "$@")" >> "$JSON_LOG_FILE" 2>/dev/null || true; }
log_debug() { echo -e "${CYAN}[DEBUG] $*${RESET}"; printf '{"ts":"%s","level":"debug","msg":%s}\n' "$(_ts)" "$(_json_quote "$@")" >> "$JSON_LOG_FILE" 2>/dev/null || true; }
log_camera_found() {
  local ip="$1" port="$2" protocol="$3" url="$4" creds="${5:-}" ts
  ts="$(date -Iseconds)"
  echo -e "${GREEN}[CAMERA FOUND] $ip:$port ($protocol) - $url${RESET}"
  cat <<EOF >> "$OUTPUT_DIR/reports/cameras.json"
{
  "timestamp": "$ts",
  "ip": "$ip",
  "port": "$port",
  "protocol": "$protocol",
  "url": "$url",
  "credentials": "$creds",
  "status": "active"
},
EOF
  CAMERAS_FOUND["$ip:$port"]="$protocol|$url|$creds"
  # Alert log
  printf '{"type":"camera_found","timestamp":"%s","ip":"%s","port":"%s","protocol":"%s","url":"%s"}\n' \
    "$ts" "$ip" "$port" "$protocol" "$url" >> "$OUTPUT_DIR/reports/alerts.log" 2>/dev/null || true
  # Structured event
  printf '{"ts":"%s","level":"event","event":"camera_found","ip":"%s","port":"%s","protocol":"%s","url":%s}\n' \
    "$(_ts)" "$ip" "$port" "$protocol" "$(_json_quote "$url")" >> "$JSON_LOG_FILE" 2>/dev/null || true
}
log_device_info() {
  local ip="$1" info="$2" type="${3:-unknown}"
  echo -e "${CYAN}[DEVICE INFO] $ip - $info ($type)${RESET}"
  DEVICE_INFO["$ip"]="$type|$info"
}

###############################################
# Dependencies install BEFORE sourcing modules #
###############################################
# Allow --help without sudo; require root for install and later scanning
DEPS_INSTALLED_FILE="$SCRIPT_DIR/.deps_installed"
if [[ ! -f "$DEPS_INSTALLED_FILE" ]]; then
  if (( EUID != 0 )); then
    echo -e "${RED}ERROR: First run must be with sudo to install dependencies.${RESET}"
    exit 1
  fi
  if [[ -f "$SCRIPT_DIR/core/install_deps.sh" ]]; then
    log "Installing dependencies (first run)... this can take a while"
    bash "$SCRIPT_DIR/core/install_deps.sh"
  fi
  touch "$DEPS_INSTALLED_FILE"
fi

# Source submodules from same dir (jq now available)
# Use explicit source paths so ShellCheck can follow them.
if [[ -f "$SCRIPT_DIR/core/setup.sh" ]]; then
  log_debug "Sourcing setup.sh"
  # shellcheck source=core/setup.sh
  source "$SCRIPT_DIR/core/setup.sh"
else
  log "ERROR: Missing file setup.sh in \"$SCRIPT_DIR/core\""; exit 1
fi

if [[ -f "$SCRIPT_DIR/core/env_setup.sh" ]]; then
  log_debug "Sourcing env_setup.sh"
  # shellcheck source=core/env_setup.sh
  source "$SCRIPT_DIR/core/env_setup.sh"
else
  log "ERROR: Missing file env_setup.sh in \"$SCRIPT_DIR/core\""; exit 1
fi

if [[ -f "$SCRIPT_DIR/core/install_deps.sh" ]]; then
  log_debug "Sourcing install_deps.sh"
  # shellcheck source=core/install_deps.sh
  source "$SCRIPT_DIR/core/install_deps.sh"
else
  log "ERROR: Missing file install_deps.sh in \"$SCRIPT_DIR/core\""; exit 1
fi

if [[ -f "$SCRIPT_DIR/core/scan_analyze.sh" ]]; then
  log_debug "Sourcing scan_analyze.sh"
  # shellcheck source=core/scan_analyze.sh
  source "$SCRIPT_DIR/core/scan_analyze.sh"
else
  log "ERROR: Missing file scan_analyze.sh in \"$SCRIPT_DIR/core\""; exit 1
fi

if [[ -f "$SCRIPT_DIR/core/cleanup.sh" ]]; then
  log_debug "Sourcing cleanup.sh"
  # shellcheck source=core/cleanup.sh
  source "$SCRIPT_DIR/core/cleanup.sh"
else
  log "ERROR: Missing file cleanup.sh in \"$SCRIPT_DIR/core\""; exit 1
fi

if [[ -f "$SCRIPT_DIR/core/iot_enumerate.sh" ]]; then
  log_debug "Sourcing iot_enumerate.sh"
  # shellcheck source=core/iot_enumerate.sh
  source "$SCRIPT_DIR/core/iot_enumerate.sh"
else
  log "ERROR: Missing file iot_enumerate.sh in \"$SCRIPT_DIR/core\""; exit 1
fi

# Enforce root for scanning operations
if (( EUID != 0 )); then
  log "ERROR: Must be run as root for scanning operations (sudo)."
  exit 1
fi

# Show dynamic runtime info banner (post env setup)
if (( !QUIET_MODE )); then
  echo -e "${CYAN}Runtime:${RESET} $(date -Iseconds) | Version: 1.0.3"
fi

# If 'K' was chosen, launch Python CLI helper in a new terminal/background
if (( LAUNCH_CLI )); then
  if command -v python3 >/dev/null 2>&1; then
    log "Launching CamSniff Python CLI (camsniff-cli) in background"
    if command -v camsniff-cli >/dev/null 2>&1; then
      nohup camsniff-cli initdb >/dev/null 2>&1 &
    else
      nohup python3 "$SCRIPT_DIR/python_core/cli.py" initdb >/dev/null 2>&1 &
    fi
  else
    log "Python3 not found; skipping CLI launch"
  fi
fi

# Load RTSP paths from local data file first; avoid network when present
LOCAL_RTSP_FILE="$SCRIPT_DIR/data/rtsp_paths.csv"
RTSP_SOURCE=""
if [[ -s "$LOCAL_RTSP_FILE" ]]; then
  RTSP_SOURCE="$LOCAL_RTSP_FILE"
else
  # Fallback to configured URL only if local list is missing
  if [[ -n "${RTSP_LIST_URL:-}" ]]; then
    curl -sfL "$RTSP_LIST_URL" -o /tmp/rtsp_paths.csv && RTSP_SOURCE="/tmp/rtsp_paths.csv" || true
  fi
fi

if [[ -n "$RTSP_SOURCE" ]]; then
  # Prefer CSV header-based extraction of the rtsp_url column and preserve placeholders
  mapfile -t RTSP_PATHS < <(
    awk -F',' '
      NR==1 {
        for (i=1;i<=NF;i++) if ($i ~ /^rtsp_url$/) col=i; next
      }
      NR>1 && col>0 {
        gsub(/^[ \\\"\t]+|[ \\\"\t]+$/, "", $col);
        if ($col ~ /^rtsp:\/\//) print $col;
      }
    ' "$RTSP_SOURCE" | tr -d '"' | sort -u
  )
  # Fallback (no header): extract any field containing rtsp:// and keep placeholders intact
  if (( ${#RTSP_PATHS[@]} == 0 )); then
    mapfile -t RTSP_PATHS < <(awk -F',' '{for(i=1;i<=NF;i++) if($i ~ /rtsp:\/\//) print $i}' "$RTSP_SOURCE" | tr -d '"' | sort -u)
  fi
else
  log "WARNING: No RTSP path list available; using minimal built-in list"
  RTSP_PATHS=(
    "rtsp://{{ip_address}}:{{port}}/video"
    "rtsp://{{ip_address}}:{{port}}/cam"
    "rtsp://{{ip_address}}:{{port}}/live"
  )
fi

if (( !QUIET_MODE )); then
  echo -e "${CYAN}RTSP Source:${RESET} ${RTSP_SOURCE:-built-in}"
  echo -e "${CYAN}Web UI:${RESET} run ./webui.sh (default http://localhost:8088)"
fi

# Final report on exit
finalize_reports() {
  sed -i '$ s/,$//' "$OUTPUT_DIR/reports/cameras.json" 2>/dev/null || true
  echo "]" >> "$OUTPUT_DIR/reports/cameras.json"
  log "Final reports saved to: $OUTPUT_DIR"
}
trap finalize_reports EXIT

# Detect interface and subnet
IF=$(ip r | awk '/default/ {print $5; exit}')
SUBNET=${TARGET_SUBNET:-$(ip -o -f inet addr show "$IF" | awk '{print $4}')}
[[ -z "$IF" || -z "$SUBNET" ]] && { log "ERROR: Could not detect interface/subnet."; exit 1; }

log "Interface: $IF"
log "Subnet: $SUBNET"

# Present summary of feature flags and output paths
if (( !QUIET_MODE )); then
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
  # Tool availability quick check (silent)
  have(){ command -v "$1" &>/dev/null && echo yes || echo no; }
  echo -e "${YELLOW}Tools:${RESET} masscan($(have masscan)) nmap($(have nmap)) ffmpeg($(have ffmpeg)) hydra($(have hydra)) tshark($(have tshark)) avahi-browse($(have avahi-browse))"
fi

# Sniffing tools
tcpdump -i "$IF" -l -n -q '(arp or (udp port 67 or udp port 68))' >/dev/null 2>&1 &
tcpdump -i "$IF" -l -n -q '(udp port 5353 or udp port 3702)' >/dev/null 2>&1 &
tshark -i "$IF" -l -Y 'rtsp||http||coap||mqtt||rtmp' -T fields -e ip.src -e tcp.port -e udp.port >/dev/null 2>&1 &

# Main scanning loop
log_debug "Entering main scanning loop"
while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep
  # Extended IoT enumeration and topology after each sweep
  if type iot_enumeration_cycle >/dev/null 2>&1; then
    log_debug "Running IoT enumeration cycle"
    iot_enumeration_cycle || true
  fi
  # Stealth mode: jittered sleep to evade simple detection
  if [[ "${STEALTH_MODE:-0}" -eq 1 ]]; then
    base=${SS:-60}; jitter=$((RANDOM % 11 - 5)); next=$((base + jitter)); (( next<5 )) && next=5
    log "Stealth sleep ${next}s (base ${base}s, jitter ${jitter}s)"
    sleep "$next"
  else
    log "Sleeping ${SS:-60}s..."
    sleep "${SS:-60}"
  fi
done
