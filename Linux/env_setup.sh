#!/usr/bin/env bash

# Configuration and environment setup with validation and extended parameters

# Default configuration
read -r -d '' DEFAULT_CFG <<'JSON'
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/usr/share/cve/cve-2025.json",
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/maaaaz/michelle/master/rtsp.txt",
  "log_file": "/var/log/camsniff.log",
  "log_level": "INFO",
  "report_file": "/var/log/camsniff_report.txt"
}
JSON

# Create configuration file if it does not exist
[[ -f camcfg.json ]] || printf '%s\n' "$DEFAULT_CFG" > camcfg.json

# Function to run jq command
JQ(){ command jq "$@"; }

# Validate configuration keys and auto-correct missing keys
validate_config() {
  local keys=("sleep_seconds" "nmap_ports" "masscan_rate" "hydra_rate" "max_streams" "cve_db" "dynamic_rtsp_url" "log_file" "log_level" "report_file")
  local changed=0
  for key in "${keys[@]}"; do
    if ! JQ -e ".${key}" camcfg.json >/dev/null 2>&1; then
      log WARN "Missing config key '$key', adding default"
      local default_val
      default_val=$(JQ -r ".${key}" <<<"$DEFAULT_CFG")
      JQ ". + {\"${key}\": ${default_val}}" camcfg.json > camcfg.tmp && mv camcfg.tmp camcfg.json
      changed=1
    fi
  done
  if (( changed )); then
    log INFO "Configuration file updated with missing keys"
  fi
}

# Load configuration values
SS=$(JQ -r '.sleep_seconds' camcfg.json)
PORTS=$(JQ -r '.nmap_ports' camcfg.json)
MASSCAN_RATE=$(JQ -r '.masscan_rate' camcfg.json)
HYDRA_RATE=$(JQ -r '.hydra_rate' camcfg.json)
MAX_STREAMS=$(JQ -r '.max_streams' camcfg.json)
CVE_DB=$(JQ -r '.cve_db' camcfg.json)
RTSP_LIST_URL=$(JQ -r '.dynamic_rtsp_url' camcfg.json)
LOG_FILE=$(JQ -r '.log_file' camcfg.json)
LOG_LEVEL=$(JQ -r '.log_level' camcfg.json)
REPORT_FILE=$(JQ -r '.report_file' camcfg.json)

# Validate config on load
validate_config
