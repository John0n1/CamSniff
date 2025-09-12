#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Debug logging
log_debug() {
  printf "\e[34m[DEBUG %s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
}

log_debug "Starting env_setup.sh"

# Ensure SCRIPT_DIR is set (works when sourced directly or via wrapper)
if [[ -z "${SCRIPT_DIR:-}" ]]; then
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  else
    SCRIPT_DIR="$(pwd)"
  fi
fi
export SCRIPT_DIR

# Ensure jq is installed
if ! command -v jq &>/dev/null; then
  log_debug "ERROR: jq is not installed. Please install it and try again."
  exit 1
fi

# Default configuration
read -r -d '' DEFAULT_CFG <<'JSON' || true
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_github_repo": "",
  "cve_cache_dir": "data/cves",
  "cve_current_year": "2025",
  "dynamic_rtsp_url": "",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "password_wordlist": "data/passwords.txt",
  "username_wordlist": "data/usernames.txt", 
  "snmp_communities": ["public", "private", "camera", "admin", "cam", "cisco", "default", "guest", "test"],
  "medusa_threads": 8,
  "enable_iot_enumeration": true,
  "enable_pcap_capture": true,
  "enable_wifi_scan": true,
  "enable_ble_scan": true,
  "enable_zigbee_zwave_scan": true,
  "stealth_mode": true,
  "enable_nmap_vuln": true
}
JSON

log_debug "Checking for camcfg.json"

# Look for config file in multiple locations
CONFIG_FILE=""
for CONFIG_PATH in "./camcfg.json" "/etc/camsniff/camcfg.json" "$HOME/.camsniff/camcfg.json"; do
  if [[ -f "$CONFIG_PATH" ]]; then
    CONFIG_FILE="$CONFIG_PATH"
    log_debug "Found configuration at: $CONFIG_FILE"
    break
  fi
done

# Create configuration file if it does not exist
if [[ -z "$CONFIG_FILE" ]]; then
  log_debug "camcfg.json not found, creating default configuration"
  CONFIG_FILE=""
  
  # Try to create config file in preferred locations
  set +e  # Temporarily disable exit on error
  for TRY_PATH in "./camcfg.json" "$HOME/.camsniff/camcfg.json" "/tmp/camcfg.json"; do
    TRY_DIR="$(dirname "$TRY_PATH")"
    if mkdir -p "$TRY_DIR" 2>/dev/null; then
      if printf '%s\n' "$DEFAULT_CFG" > "$TRY_PATH" 2>/dev/null; then
        CONFIG_FILE="$TRY_PATH"
        log_debug "Created default configuration at: $CONFIG_FILE"
        break
      fi
    fi
  done
  set -e  # Re-enable exit on error
  
  if [[ -z "$CONFIG_FILE" ]]; then
    log_debug "ERROR: Unable to create configuration file"
    exit 1
  fi
fi

log_debug "Using configuration file: $CONFIG_FILE"

# Function to run jq command
JQ(){ command jq "$@" || { log_debug "jq command failed"; exit 1; }; }

log_debug "Loading configuration values"

# Load configuration values
SS=$(JQ -r '.sleep_seconds' "$CONFIG_FILE") || { log_debug "Failed to load sleep_seconds"; exit 1; }
log_debug "Loaded sleep_seconds: $SS"

PORTS=$(JQ -r '.nmap_ports' "$CONFIG_FILE") || { log_debug "Failed to load nmap_ports"; exit 1; }
log_debug "Loaded nmap_ports: $PORTS"

MASSCAN_RATE=$(JQ -r '.masscan_rate' "$CONFIG_FILE") || { log_debug "Failed to load masscan_rate"; exit 1; }
log_debug "Loaded masscan_rate: $MASSCAN_RATE"

HYDRA_RATE=$(JQ -r '.hydra_rate' "$CONFIG_FILE") || { log_debug "Failed to load hydra_rate"; exit 1; }
log_debug "Loaded hydra_rate: $HYDRA_RATE"

MAX_STREAMS=$(JQ -r '.max_streams' "$CONFIG_FILE") || { log_debug "Failed to load max_streams"; exit 1; }
log_debug "Loaded max_streams: $MAX_STREAMS"

CVE_GITHUB_REPO=$(JQ -r '.cve_github_repo' "$CONFIG_FILE") || { log_debug "Failed to load cve_github_repo"; exit 1; }
log_debug "Loaded cve_github_repo: $CVE_GITHUB_REPO"

CVE_CACHE_DIR=$(JQ -r '.cve_cache_dir' "$CONFIG_FILE") || { log_debug "Failed to load cve_cache_dir"; exit 1; }
log_debug "Loaded cve_cache_dir: $CVE_CACHE_DIR"

CVE_CURRENT_YEAR=$(JQ -r '.cve_current_year' "$CONFIG_FILE") || { log_debug "Failed to load cve_current_year"; exit 1; }
log_debug "Loaded cve_current_year: $CVE_CURRENT_YEAR"

RTSP_LIST_URL=$(JQ -r '.dynamic_rtsp_url' "$CONFIG_FILE") || { log_debug "Failed to load dynamic_rtsp_url"; exit 1; }
log_debug "Loaded dynamic_rtsp_url: $RTSP_LIST_URL"

# Auto-correct legacy RTSP URL source if found in existing configs
if [[ "$RTSP_LIST_URL" == *"CamioCam/rtsp"* ]]; then
  log_debug "Found legacy RTSP list URL; switching to project maintained list"
  RTSP_LIST_URL="https://github.com/John0n1/CamSniff/blob/4d682edf7b4512562d24ccdf863332952637094d/data/rtsp_paths.csv"
fi

# New: wordlist for directory brute forcing
DIRB_WORDLIST=$(JQ -r '.dirb_wordlist' "$CONFIG_FILE") || { log_debug "Failed to load dirb_wordlist"; exit 1; }
log_debug "Loaded dirb_wordlist: $DIRB_WORDLIST"

# New: password and username wordlists for authentication brute forcing
PASSWORD_WORDLIST=$(JQ -r '.password_wordlist' "$CONFIG_FILE") || { log_debug "Failed to load password_wordlist"; exit 1; }
log_debug "Loaded password_wordlist: $PASSWORD_WORDLIST"

USERNAME_WORDLIST=$(JQ -r '.username_wordlist' "$CONFIG_FILE") || { log_debug "Failed to load username_wordlist"; exit 1; }
log_debug "Loaded username_wordlist: $USERNAME_WORDLIST"

# New: SNMP communities list -> temp file for onesixtyone
log_debug "Loading SNMP communities"
mapfile -t SNMP_COMM_ARRAY < <(JQ -r '.snmp_communities[]' "$CONFIG_FILE") || { log_debug "Failed to load snmp_communities"; exit 1; }
log_debug "Loaded SNMP communities: ${SNMP_COMM_ARRAY[*]}"

# Create SNMP community file in /tmp; fall back to a unique file if needed
SNMP_COMM_FILE=/tmp/.snmp_comms.txt
if ! printf "%s\n" "${SNMP_COMM_ARRAY[@]}" > "$SNMP_COMM_FILE" 2>/dev/null; then
  # If the default path is not writable (e.g., owned by root), create a unique temp file
  SNMP_COMM_FILE=$(mktemp /tmp/.snmp_comms.XXXXXX)
  printf "%s\n" "${SNMP_COMM_ARRAY[@]}" > "$SNMP_COMM_FILE" || { log_debug "Failed to write SNMP_COMM_FILE"; exit 1; }
fi
SNMP_COMMUNITIES="$SNMP_COMM_FILE"
log_debug "SNMP_COMM_FILE created at $SNMP_COMM_FILE"

# New: threads for Medusa fuzzing
MEDUSA_THREADS=$(JQ -r '.medusa_threads' "$CONFIG_FILE") || { log_debug "Failed to load medusa_threads"; exit 1; }
log_debug "Loaded medusa_threads: $MEDUSA_THREADS"

# Feature flags
ENABLE_IOT_ENUMERATION=$(JQ -r '.enable_iot_enumeration // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
ENABLE_PCAP_CAPTURE=$(JQ -r '.enable_pcap_capture // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
ENABLE_WIFI_SCAN=$(JQ -r '.enable_wifi_scan // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
ENABLE_BLE_SCAN=$(JQ -r '.enable_ble_scan // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
ENABLE_ZIGBEE_ZWAVE_SCAN=$(JQ -r '.enable_zigbee_zwave_scan // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
STEALTH_MODE=$(JQ -r '.stealth_mode // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
ENABLE_NMAP_VULN=$(JQ -r '.enable_nmap_vuln // true' "$CONFIG_FILE" | sed 's/true/1/; s/false/0/')
ENABLE_BRUTE_FORCE=${ENABLE_BRUTE_FORCE:-1}
export ENABLE_IOT_ENUMERATION ENABLE_PCAP_CAPTURE ENABLE_WIFI_SCAN ENABLE_BLE_SCAN ENABLE_ZIGBEE_ZWAVE_SCAN STEALTH_MODE ENABLE_NMAP_VULN ENABLE_BRUTE_FORCE
log_debug "Feature flags: IoT=$ENABLE_IOT_ENUMERATION PCAP=$ENABLE_PCAP_CAPTURE WiFi=$ENABLE_WIFI_SCAN BLE=$ENABLE_BLE_SCAN Zig=$ENABLE_ZIGBEE_ZWAVE_SCAN Stealth=$STEALTH_MODE NmapVuln=$ENABLE_NMAP_VULN"

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
if ! validate_cve_dependencies; then
  CVE_CHECK_LIMITED=1
  export CVE_CHECK_LIMITED
  log_debug "CVE system dependencies validation failed. CVE checking will be limited."
else
  CVE_CHECK_LIMITED=0
  export CVE_CHECK_LIMITED
fi

log_debug "Finished env_setup.sh"

# Runtime variables expected by scanners
FIRST_RUN=${FIRST_RUN:-1}

# Default credential sets for HTTP camera endpoints
declare -a HTTP_CREDS

# Generate HTTP_CREDS from wordlists if available, otherwise use hardcoded fallback
set +u  # Temporarily disable unset variable checking for this section

# Resolve wordlist paths: support absolute paths, CWD paths, and repo-relative under SCRIPT_DIR
resolve_path(){
  local p="$1"
  if [[ -z "$p" ]]; then return 1; fi
  if [[ -f "$p" ]]; then printf "%s" "$p"; return 0; fi
  if [[ -f "$SCRIPT_DIR/$p" ]]; then printf "%s" "$SCRIPT_DIR/$p"; return 0; fi
  return 1
}

USERLIST_PATH=""; PASSLIST_PATH=""
if USERLIST_PATH="$(resolve_path "${USERNAME_WORDLIST:-}")" && \
   PASSLIST_PATH="$(resolve_path "${PASSWORD_WORDLIST:-}")"; then
  log_debug "Generating HTTP_CREDS from wordlists"
  
  # Read usernames and passwords into arrays first
  mapfile -t top_users < <(grep -v "^#" "$USERLIST_PATH" | grep -v "^$" | head -5) || true
  mapfile -t top_passwords < <(grep -v "^#" "$PASSLIST_PATH" | grep -v "^$" | head -8) || true
  
  # Generate combinations if we have data
  if [[ ${#top_users[@]} -gt 0 && ${#top_passwords[@]} -gt 0 ]]; then
    HTTP_CREDS=()
    for user in "${top_users[@]}"; do
      [[ "$user" == "__EMPTY__" ]] && user=""
      for pass in "${top_passwords[@]}"; do
        [[ "$pass" == "__EMPTY__" ]] && pass=""
        HTTP_CREDS+=("$user:$pass")
      done
    done
    
    # Add empty credentials if they were in the original wordlists
    if grep -q "^__EMPTY__$" "$USERLIST_PATH" 2>/dev/null || 
       grep -q "^__EMPTY__$" "$PASSLIST_PATH" 2>/dev/null; then
      HTTP_CREDS+=(":")
    fi
    
    log_debug "Generated ${#HTTP_CREDS[@]} HTTP credential combinations"
  else
    log_debug "Failed to read wordlists, using fallback HTTP_CREDS"
    HTTP_CREDS=(
      "admin:admin"
      "admin:12345"
      "root:root"
      "user:user"
      "guest:guest"
      ":"      # empty creds for open endpoints
    )
  fi
else
  log_debug "Using fallback HTTP_CREDS"
  HTTP_CREDS=(
    "admin:admin"
    "admin:12345"
    "root:root"
    "user:user"
    "guest:guest"
    ":"      # empty creds for open endpoints
  )
fi
set -u  # Re-enable unset variable checking

# Optional hydra files can be overridden from environment; defaults generated on the fly
HYDRA_USER_FILE=${HYDRA_USER_FILE:-}
HYDRA_PASS_FILE=${HYDRA_PASS_FILE:-}
HYDRA_COMBO_FILE=${HYDRA_COMBO_FILE:-}

