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
  "cve_github_repo": "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves",
  "cve_cache_dir": "/tmp/cve_cache",
  "cve_current_year": "2025",
  "dynamic_rtsp_url": "https://github.com/CamioCam/rtsp/blob/master/cameras/paths.csv",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "snmp_communities": ["public", "private", "camera", "admin", "cam", "cisco", "default", "guest", "test"],
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

CVE_GITHUB_REPO=$(JQ -r '.cve_github_repo' camcfg.json) || { log_debug "Failed to load cve_github_repo"; exit 1; }
log_debug "Loaded cve_github_repo: $CVE_GITHUB_REPO"

CVE_CACHE_DIR=$(JQ -r '.cve_cache_dir' camcfg.json) || { log_debug "Failed to load cve_cache_dir"; exit 1; }
log_debug "Loaded cve_cache_dir: $CVE_CACHE_DIR"

CVE_CURRENT_YEAR=$(JQ -r '.cve_current_year' camcfg.json) || { log_debug "Failed to load cve_current_year"; exit 1; }
log_debug "Loaded cve_current_year: $CVE_CURRENT_YEAR"

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

# Create CVE cache directory
mkdir -p "$CVE_CACHE_DIR"
log_debug "CVE cache directory created: $CVE_CACHE_DIR"

# Initialize CVE checking system
init_cve_system() {
  log_debug "Initializing CVE system"
  
  # Create a simple index file for cached CVEs
  CVE_INDEX_FILE="$CVE_CACHE_DIR/cve_index.json"
  if [[ ! -f "$CVE_INDEX_FILE" ]]; then
    echo "{}" > "$CVE_INDEX_FILE"
    log_debug "Created CVE index file: $CVE_INDEX_FILE"
  fi
}

# Call initialization
init_cve_system

# Validate CVE system dependencies
validate_cve_dependencies() {
  log_debug "Validating CVE system dependencies"
  
  # Check if requests library is available
  if ! python3 -c "import requests; import json" 2>/dev/null; then
    log_debug "WARNING: Python requests library not available, CVE checking may be limited"
    return 1
  fi
  
  # Check internet connectivity for GitHub API
  if ! curl -sf --connect-timeout 5 "https://api.github.com" >/dev/null 2>&1; then
    log_debug "WARNING: GitHub API not accessible, CVE checking will use cached data only"
    return 1
  fi
  
  log_debug "CVE system dependencies validated successfully"
  return 0
}

# Call validation during initialization
validate_cve_dependencies

log_debug "Finished env_setup.sh"
