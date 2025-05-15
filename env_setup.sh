#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Debug logging
log_debug() {
  printf "\e[34m[DEBUG %s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
}

log_debug "Starting env_setup.sh"

# Ensure jq is installed
if ! command -v jq &>/dev/null; then
  log_debug "ERROR: jq is not installed. Please install it and try again."
  exit 1
fi

# Default configuration
read -r -d '' DEFAULT_CFG <<'JSON'
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/usr/share/cve/cve-2025.json",
  "dynamic_rtsp_url": "https://github.com/CamioCam/rtsp/blob/master/cameras/paths.csv",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "snmp_communities": ["public", "private", "camera", "admin"],
  "medusa_threads": 8
}
JSON

log_debug "Checking for camcfg.json"

# Create configuration file if it does not exist
if [[ ! -f camcfg.json ]]; then
  log_debug "camcfg.json not found, creating default configuration"
  printf '%s\n' "$DEFAULT_CFG" > camcfg.json || { log_debug "Failed to create camcfg.json"; exit 1; }
fi

log_debug "camcfg.json exists or was created successfully"

# Function to run jq command
JQ(){ command jq "$@" || { log_debug "jq command failed"; exit 1; }; }

log_debug "Loading configuration values"

# Load configuration values
SS=$(JQ -r '.sleep_seconds' camcfg.json) || { log_debug "Failed to load sleep_seconds"; exit 1; }
log_debug "Loaded sleep_seconds: $SS"

PORTS=$(JQ -r '.nmap_ports' camcfg.json) || { log_debug "Failed to load nmap_ports"; exit 1; }
log_debug "Loaded nmap_ports: $PORTS"

MASSCAN_RATE=$(JQ -r '.masscan_rate' camcfg.json) || { log_debug "Failed to load masscan_rate"; exit 1; }
log_debug "Loaded masscan_rate: $MASSCAN_RATE"

HYDRA_RATE=$(JQ -r '.hydra_rate' camcfg.json) || { log_debug "Failed to load hydra_rate"; exit 1; }
log_debug "Loaded hydra_rate: $HYDRA_RATE"

MAX_STREAMS=$(JQ -r '.max_streams' camcfg.json) || { log_debug "Failed to load max_streams"; exit 1; }
log_debug "Loaded max_streams: $MAX_STREAMS"

CVE_DB=$(JQ -r '.cve_db' camcfg.json) || { log_debug "Failed to load cve_db"; exit 1; }
log_debug "Loaded cve_db: $CVE_DB"

RTSP_LIST_URL=$(JQ -r '.dynamic_rtsp_url' camcfg.json) || { log_debug "Failed to load dynamic_rtsp_url"; exit 1; }
log_debug "Loaded dynamic_rtsp_url: $RTSP_LIST_URL"

# New: wordlist for directory brute forcing
DIRB_WORDLIST=$(JQ -r '.dirb_wordlist' camcfg.json) || { log_debug "Failed to load dirb_wordlist"; exit 1; }
log_debug "Loaded dirb_wordlist: $DIRB_WORDLIST"

# New: SNMP communities list -> temp file for onesixtyone
log_debug "Loading SNMP communities"
mapfile -t SNMP_COMM_ARRAY < <(JQ -r '.snmp_communities[]' camcfg.json) || { log_debug "Failed to load snmp_communities"; exit 1; }
log_debug "Loaded SNMP communities: ${SNMP_COMM_ARRAY[*]}"

SNMP_COMM_FILE=/tmp/.snmp_comms.txt
printf "%s\n" "${SNMP_COMM_ARRAY[@]}" > "$SNMP_COMM_FILE" || { log_debug "Failed to write SNMP_COMM_FILE"; exit 1; }
SNMP_COMMUNITIES="$SNMP_COMM_FILE"
log_debug "SNMP_COMM_FILE created at $SNMP_COMM_FILE"

# New: threads for Medusa fuzzing
MEDUSA_THREADS=$(JQ -r '.medusa_threads' camcfg.json) || { log_debug "Failed to load medusa_threads"; exit 1; }
log_debug "Loaded medusa_threads: $MEDUSA_THREADS"

log_debug "Finished env_setup.sh"
