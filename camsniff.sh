#!/usr/bin/env bash
###############################################################################
# CamSniff 4.10 – bY https://github.com/John0n1/CamSniff
###############################################################################
set -euo pipefail
IFS=$'\n\t'
declare -A STREAMS        
declare -A HOSTS_SCANNED  
FIRST_RUN=1

# Debug logging
log_debug() {
  printf "\e[34m[DEBUG %s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
}

log_debug "Starting camsniff.sh"

# Define Python virtualenv path so abort branch can remove it
VENV="$PWD/.camvenv"

#— Pre-split script sourcing
log_debug "Sourcing setup.sh"
if ! source "${BASH_SOURCE%/*}/setup.sh"; then
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
    if ! source "${BASH_SOURCE%/*}/setup.sh"; then
      log "ERROR: Failed to run setup.sh"
      exit 1
    fi

    # Run env_setup.sh to ensure environment configuration
    if ! source "${BASH_SOURCE%/*}/env_setup.sh"; then
      log "ERROR: Failed to run env_setup.sh"
      exit 1
    fi

    # Run install_deps.sh to install required dependencies
    if ! bash "${BASH_SOURCE%/*}/install_deps.sh"; then
      log "ERROR: Failed to run install_deps.sh"
      exit 1
    fi

    touch .deps_installed
  fi
fi

#— Load environment and start scanning logic
log_debug "Sourcing env_setup.sh"
if ! source "${BASH_SOURCE%/*}/env_setup.sh"; then
  log "ERROR: Failed to source env_setup.sh"
  exit 1
fi

log_debug "Sourcing scan_analyze.sh"
if ! source "${BASH_SOURCE%/*}/scan_analyze.sh"; then
  log "ERROR: Failed to source scan_analyze.sh"
  exit 1
fi

log_debug "Sourcing cleanup.sh"
if ! source "${BASH_SOURCE%/*}/cleanup.sh"; then
  log "ERROR: Failed to source cleanup.sh"
  exit 1
fi

#— Pre-scan prompt
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

log_debug "Starting network info and taps"

#— Network info & taps
IF=$(ip r | awk '/default/ {print $5;exit}')
SUBNET=$(ip -o -f inet addr show "$IF" | awk '{print $4}')
if [[ -z "$IF" || -z "$SUBNET" ]]; then
  log "Could not determine network interface or subnet. Exiting."
  exit 1
fi
log "IF=$IF SUBNET=$SUBNET"
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

while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep
  log "Sleeping ${SS}s…"
  sleep "$SS"
done
