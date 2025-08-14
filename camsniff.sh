#!/usr/bin/env bash
###############################################################################
# CamSniff 1.0.1 – Camera Reconnaissance & Scanner
# https://github.com/John0n1/CamSniff
###############################################################################
set -euo pipefail
IFS=$'\n\t'

# Command line options parsing
SKIP_PROMPT=0
QUIET_MODE=0
AUTO_MODE=0
TARGET_SUBNET=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -y|--yes) SKIP_PROMPT=1; shift ;;
    -q|--quiet) QUIET_MODE=1; shift ;;
    -a|--auto) AUTO_MODE=1; SKIP_PROMPT=1; shift ;;
    -t|--target) TARGET_SUBNET="$2"; shift 2 ;;
    -h|--help)
      echo "CamSniff 1.0.1 - Camera Reconnaissance Tool & Scanner"
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

# Display banner
if (( !QUIET_MODE )); then
  echo -e "${CYAN}CamSniff is a powerful tool designed to:${RESET}"
  echo -e "${GREEN}- Discover and analyze network-connected cameras."
  echo -e "- Perform RTSP, HTTP, CoAP, and RTMP scans."
  echo -e "- Identify vulnerabilities and brute-force credentials."
  echo -e "- Generate AI-based insights from camera streams.${RESET}"
  cat << 'EOF'
.--------------. | .--------------. | .--------------. | .--------------. | .--------------. | .--------------. | .--------------. | .--------------. 
|     ______   | | |      __      | | | ____    ____ | | |    _______   | | | ____  _____  | | |     _____    | | |  _________   | | |  _________   |
|   .' ___  |  | | |     /  \     | | ||_   \  /   _|| | |   /  ___  |  | | ||_   \|_   _| | | |    |_   _|   | | | |_   ___  |  | | | |_   ___  |  |
|  / .'   \_|  | | |    / /\ \    | | |  |   \/   |  | | |  |  (__ \_|  | | |  |   \ | |   | | |      | |     | | |   | |_  \_|  | | |   | |_  \_|  |
|  | |         | | |   / ____ \   | | |  | |\  /| |  | | |   '.___`-.   | | |  | |\ \| |   | | |      | |     | | |   |  _|      | | |   |  _|      |
|  `.___.'\    | | | _/ /    \ \_ | | | _| |_\/_| |_ | | |  |`\____) |  | | | _| |_\   |_  | | |     _| |_    | | |  _| |_       | | |  _| |_       |
|   `._____.'  | | ||____|  |____|| | ||_____||_____|| | |  |_______.'  | | ||_____|\____| | | |    |_____|   | | | |_____|      | | | |_____|      |
|              | | |              | | |              | | |              | | |              | | |              | | |              | | |              |
'--------------' | '--------------' | '--------------' | '--------------' | '--------------' | '--------------' | '--------------' | '--------------'
EOF
  echo -e "${YELLOW}CamSniff 1.0.1 – Camera Reconnaissance${RESET}"
  echo -e "${YELLOW}What will happen:${RESET}"
  echo -e "${CYAN}1.${RESET} Dependencies will be checked and installed if missing."
  echo -e "${CYAN}2.${RESET} Network scanning will begin to identify active devices."
  echo -e "${CYAN}3.${RESET} Camera streams will be analyzed and displayed."
  echo -e "${CYAN}4.${RESET} Results will be saved to structured output directory."
  echo -e "${CYAN}5.${RESET} You can choose to start the scan or exit at any time."
fi

# Confirmation prompt
if (( !SKIP_PROMPT )); then
  while true; do
    read -rp "$(echo -e "${CYAN}Start CamSniff? (Y/N): ${RESET}")" yn
    case $yn in
      [Yy]*) break ;;
      [Nn]*) echo -e "${RED}Exiting. Goodbye!${RESET}"; exit 0 ;;
      *) echo -e "${YELLOW}Please press 'Y' to start or 'N' to exit.${RESET}" ;;
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

# Python venv path
VENV="$SCRIPT_DIR/.camvenv"

# Logging and output
declare -A STREAMS HOSTS_SCANNED CAMERAS_FOUND DEVICE_INFO
echo "[" > "$OUTPUT_DIR/reports/cameras.json"

log()       { echo -e "${GREEN}[+] $*${RESET}"; }
log_debug() { echo -e "${CYAN}[DEBUG] $*${RESET}"; }
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
}
log_device_info() {
  local ip="$1" info="$2" type="${3:-unknown}"
  echo -e "${CYAN}[DEVICE INFO] $ip - $info ($type)${RESET}"
  DEVICE_INFO["$ip"]="$type|$info"
}

# Source submodules from same dir
for FILE in setup.sh env_setup.sh install_deps.sh scan_analyze.sh cleanup.sh; do
  if [[ -f "$SCRIPT_DIR/$FILE" ]]; then
    log_debug "Sourcing $FILE"
    source "$SCRIPT_DIR/$FILE"
  else
    log "ERROR: Missing file $FILE in $SCRIPT_DIR"
    exit 1
  fi
done

# First-time dependency marker
DEPS_INSTALLED_FILE="$SCRIPT_DIR/.deps_installed"
if [[ ! -f "$DEPS_INSTALLED_FILE" ]]; then
  if (( EUID != 0 )); then
    log "ERROR: Must be run as root to install dependencies."
    exit 1
  fi
  touch "$DEPS_INSTALLED_FILE"
fi

# Load RTSP paths using URL from configuration
if curl -sfL "$RTSP_LIST_URL" -o /tmp/rtsp_paths.csv; then
  mapfile -t RTSP_PATHS < <(awk -F'\t' '/^.*rtsp:\/\// {print $4}' /tmp/rtsp_paths.csv | sed 's/{{.*}}//g' | sort -u)
else
  log "ERROR: Failed to fetch RTSP paths from $RTSP_LIST_URL"
  exit 1
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

# Sniffing tools
tcpdump -i "$IF" -l -n -q '(arp or (udp port 67 or udp port 68))' >/dev/null 2>&1 &
tcpdump -i "$IF" -l -n -q '(udp port 5353 or udp port 3702)' >/dev/null 2>&1 &
tshark -i "$IF" -l -Y 'rtsp||http||coap||mqtt||rtmp' -T fields -e ip.src -e tcp.port -e udp.port >/dev/null 2>&1 &

# Main scanning loop
log_debug "Entering main scanning loop"
while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep
  log "Sleeping ${SS:-60}s..."
  sleep "${SS:-60}"
done