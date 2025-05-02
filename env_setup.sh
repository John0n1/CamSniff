#!/usr/bin/env bash

# Configuration and environment setup

# Default configuration
read -r -d '' DEFAULT_CFG <<'JSON'
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/usr/share/cve/cve-2025.json",
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/maaaaz/michelle/master/rtsp.txt"
}
JSON

# Create configuration file if it does not exist
[[ -f camcfg.json ]] || printf '%s\n' "$DEFAULT_CFG" > camcfg.json

# Function to run jq command
JQ(){ command jq "$@"; }

# Load configuration values
SS=$(JQ -r '.sleep_seconds' camcfg.json)
PORTS=$(JQ -r '.nmap_ports' camcfg.json)
MASSCAN_RATE=$(JQ -r '.masscan_rate' camcfg.json)
HYDRA_RATE=$(JQ -r '.hydra_rate' camcfg.json)
MAX_STREAMS=$(JQ -r '.max_streams' camcfg.json)
CVE_DB=$(JQ -r '.cve_db' camcfg.json)
RTSP_LIST_URL=$(JQ -r '.dynamic_rtsp_url' camcfg.json)
