#!/usr/bin/env bash
###############################################################################
# CamSniff 1.0.1 – Enhanced Camera Reconnaissance Tool
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
    -y|--yes)
      SKIP_PROMPT=1
      shift
      ;;
    -q|--quiet)
      QUIET_MODE=1
      shift
      ;;
    -a|--auto)
      AUTO_MODE=1
      SKIP_PROMPT=1
      shift
      ;;
    -t|--target)
      TARGET_SUBNET="$2"
      shift 2
      ;;
    -h|--help)
      echo "CamSniff 1.0.1 - Enhanced Camera Reconnaissance Tool"
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
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

# Display banner unless in quiet mode
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
  echo -e "${YELLOW}CamSniff 1.0.1 – Enhanced Camera Reconnaissance${RESET}"
  echo -e "${YELLOW}What will happen:${RESET}"
  echo -e "${CYAN}1.${RESET} Dependencies will be checked and installed if missing."
  echo -e "${CYAN}2.${RESET} Network scanning will begin to identify active devices."
  echo -e "   ${RED}- This can take some time depending on the network size (up to 15 minutes)."
  echo -e "   - The scan is a very intensive process and may even affect the network.${RESET}"
  echo -e "${CYAN}3.${RESET} Camera streams will be analyzed and displayed."
  echo -e "${CYAN}4.${RESET} Results will be saved to structured output directory."
  echo -e "${CYAN}5.${RESET} You can choose to start the scan or exit at any time (Ctrl+C)."
  echo -e "   - This will clean up the environment and stop all processes."
  echo -e "Press 'Y' to start or 'N' to exit.${RESET}'"
fi

# Launch prompt loop (skip if automated)
if (( !SKIP_PROMPT )); then
  while true; do
    read -rp "$(echo -e "${CYAN}Start CamSniff? (Y/N): ${RESET}")" yn
    case $yn in
      [Yy]*) break ;;  # proceed to main script
      [Nn]*) echo -e "${RED}Exiting. Goodbye!${RESET}"; exit 0;;
      *) echo -e "${YELLOW}Please press 'Y' to start or 'N' to exit.${RESET}";;
    esac
  done
else
  echo -e "${GREEN}Auto-mode enabled, starting scan...${RESET}"
fi

declare -A STREAMS        
declare -A HOSTS_SCANNED  
declare -A CAMERAS_FOUND
declare -A DEVICE_INFO
FIRST_RUN=1

# Enhanced logging and output directories
OUTPUT_DIR="/tmp/camsniff_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"/{logs,screenshots,reports}

# Initialize JSON report file
echo "[" > "$OUTPUT_DIR/reports/cameras.json"

# Debug logging
log_debug() {
  printf "\e[34m[DEBUG %s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
}

# Enhanced logging with structured output
log_camera_found() {
  local ip="$1" port="$2" protocol="$3" url="$4" creds="${5:-}"
  local timestamp="$(date -Iseconds)"
  
  # Log to console
  printf "\e[32m[CAMERA FOUND %s]\e[0m %s:%s (%s) - %s\n" "$(date +'%H:%M:%S')" "$ip" "$port" "$protocol" "$url"
  
  # Log to structured file
  {
    echo "{"
    echo "  \"timestamp\": \"$timestamp\","
    echo "  \"ip\": \"$ip\","
    echo "  \"port\": \"$port\","
    echo "  \"protocol\": \"$protocol\","
    echo "  \"url\": \"$url\","
    echo "  \"credentials\": \"$creds\","
    echo "  \"status\": \"active\""
    echo "},"
  } >> "$OUTPUT_DIR/reports/cameras.json"
  
  # Store in memory for summary
  CAMERAS_FOUND["$ip:$port"]="$protocol|$url|$creds"
}

# Enhanced device info logging
log_device_info() {
  local ip="$1" info="$2" type="${3:-unknown}"
  
  printf "\e[36m[DEVICE INFO %s]\e[0m %s - %s (%s)\n" "$(date +'%H:%M:%S')" "$ip" "$info" "$type"
  
  # Store device info
  DEVICE_INFO["$ip"]="$type|$info"
}

log_debug "Starting camsniff.sh"

# Define Python virtualenv path so abort branch can remove it
VENV="$PWD/.camvenv"

# Determine data directory for supporting scripts
SCRIPT_PATH=$(readlink -f "$0")
if [[ "$(basename "$SCRIPT_PATH")" == "camsniff" && "$(dirname "$SCRIPT_PATH")" == "/usr/bin" ]]; then
  # Running as installed package
  DATADIR="/usr/share/camsniff"
else
  # Running from source directory
  DATADIR="$(dirname "$SCRIPT_PATH")"
fi

#— Pre-split script sourcing
log_debug "Sourcing setup.sh"
if ! source "$DATADIR/setup.sh"; then
  log "ERROR: Failed to source setup.sh"
  exit 1
fi

#— Install dependencies once (requires root)
log_debug "Checking dependencies"
if [[ -z "${SKIP_DEPS-}" && ! -f .deps_installed ]]; then
  log_debug "Running setup.sh, env_setup.sh, and install_deps.sh to handle dependencies"
  if (( EUID != 0 )); then
    log "ERROR: This script must be run as root to install dependencies."
    exit 1
  else
    # Run setup.sh to ensure critical tools are installed
    if ! source "$DATADIR/setup.sh"; then
      log "ERROR: Failed to run setup.sh"
      exit 1
    fi

    # Run env_setup.sh to ensure environment configuration
    if ! source "$DATADIR/env_setup.sh"; then
      log "ERROR: Failed to run env_setup.sh"
      exit 1
    fi

    # Run install_deps.sh to install required dependencies
    if ! bash "$DATADIR/install_deps.sh"; then
      log "ERROR: Failed to run install_deps.sh"
      exit 1
    fi

    touch .deps_installed
  fi
fi

#— Load environment and start scanning logic
log_debug "Sourcing env_setup.sh"
if ! source "$DATADIR/env_setup.sh"; then
  log "ERROR: Failed to source env_setup.sh"
  exit 1
fi

log_debug "Sourcing scan_analyze.sh"
if ! source "$DATADIR/scan_analyze.sh"; then
  log "ERROR: Failed to source scan_analyze.sh"
  exit 1
fi

log_debug "Sourcing cleanup.sh"
if ! source "$DATADIR/cleanup.sh"; then
  log "ERROR: Failed to source cleanup.sh"
  exit 1
fi

#— Pre-scan prompt
if (( !AUTO_MODE )); then
  while true; do
    read -rp "Start scanning? (Y/N) " yn
    case $yn in
      [Yy]*) 
        log "Scanning… Ctrl-C to stop"
        (
          sleep 1
        ) &
        pid=$!
        loading_bar "preparing scan" $pid
        wait $pid
        printf "\r\033[K"
        break
        ;;
      [Nn]*) log "Abort—cleanup & delete"; deactivate 2>/dev/null || true; cleanup; rm -rf "$VENV" camcfg.json plugins; exit ;;
      *) echo "Y or N";;
    esac
  done
else
  log "Auto-mode: Starting scan immediately..."
fi

log_debug "Starting network info and taps"

#— Network info & taps
IF=$(ip r | awk '/default/ {print $5;exit}')
if [[ -n "$TARGET_SUBNET" ]]; then
  SUBNET="$TARGET_SUBNET"
  log "Using custom target subnet: $SUBNET"
else
  SUBNET=$(ip -o -f inet addr show "$IF" | awk '{print $4}')
fi

if [[ -z "$IF" || -z "$SUBNET" ]]; then
  log "Could not determine network interface or subnet. Exiting."
  exit 1
fi
log "IF=$IF SUBNET=$SUBNET Output: $OUTPUT_DIR"
avahi-daemon --start 2>/dev/null || true
tcpdump -i "$IF" -l -n -q '(arp or (udp port 67 or udp port 68))' >/dev/null 2>&1 &
tcpdump -i "$IF" -l -n -q '(udp port 5353 or udp port 3702)' >/dev/null 2>&1 &
tshark -i "$IF" -l -Y 'rtsp||http||coap||mqtt||rtmp' -T fields -e ip.src -e tcp.port -e udp.port >/dev/null 2>&1 &

log_debug "Fetching RTSP paths"

# Validate RTSP_LIST_URL
if ! curl -sfI "$RTSP_LIST_URL" &>/dev/null; then
  log "ERROR: RTSP_LIST_URL is not reachable: $RTSP_LIST_URL"
  exit 1
fi

# Fetch and parse RTSP paths from the CSV file
if curl -sfL "$RTSP_LIST_URL" -o /tmp/rtsp_paths.csv; then
  log_debug "Parsing RTSP paths from CSV"
  mapfile -t RTSP_PATHS < <(awk -F'\t' '/^.*rtsp:\/\// {print $4}' /tmp/rtsp_paths.csv | sed 's/{{.*}}//g' | sort -u)
else
  log "ERROR: Failed to fetch RTSP paths from $RTSP_LIST_URL"
  exit 1
fi

if [[ ${#RTSP_PATHS[@]} -eq 0 ]]; then
  log "ERROR: No RTSP paths found in the CSV file."
  exit 1
fi

log_debug "Loaded ${#RTSP_PATHS[@]} RTSP paths"

HTTP_CREDS=(admin:admin admin:123456 admin:1234 admin:password root:root root:123456 root:toor user:user guest:guest :admin admin:)
HYDRA_FILE=/tmp/.hydra_creds.txt
printf "%s\n" "${HTTP_CREDS[@]}" > "$HYDRA_FILE"

loading_bar(){
  local msg="$1" pid="$2" delay=0.2
  printf "%s" "$msg"
  if ! kill -0 "$pid" 2>/dev/null; then
    printf "\n[ERROR] Invalid PID: %s\n" "$pid"
    return
  fi
  while kill -0 "$pid" 2>/dev/null; do
    printf "."
    sleep "$delay"
  done
  printf "\n"
}

log_debug "Entering main scanning loop"

# Cleanup function for JSON finalization
finalize_reports() {
  if [[ -f "$OUTPUT_DIR/reports/cameras.json" ]]; then
    # Remove trailing comma and close JSON array
    sed -i '$ s/,$//' "$OUTPUT_DIR/reports/cameras.json" 2>/dev/null || true
    echo "]" >> "$OUTPUT_DIR/reports/cameras.json"
  fi
  log "Final reports saved to: $OUTPUT_DIR"
}

# Set trap for cleanup
trap finalize_reports EXIT

while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep
  log "Sleeping ${SS}s…"
  sleep "$SS"
done
