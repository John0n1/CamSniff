#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

echo "[INFO] env_setup offline config test"

[[ -x ./env_setup.sh ]] || { echo "[ERROR] env_setup.sh missing or not executable"; exit 1; }

# Backup existing config if present
BACKUP=""
if [[ -f ./camcfg.json ]]; then
  BACKUP=$(mktemp /tmp/camcfg.backup.XXXXXX)
  cp ./camcfg.json "$BACKUP"
fi

cat > ./camcfg.json <<'JSON'
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

# Source and check values (should prefer ./camcfg.json)
source ./env_setup.sh

[[ -n "${CVE_CACHE_DIR:-}" ]] || { echo "[ERROR] CVE_CACHE_DIR not set"; exit 1; }
trim_cve=$(printf "%s" "${CVE_GITHUB_REPO:-}" | tr -d '\r\n\t ') ; echo "[DEBUG] CVE_GITHUB_REPO='${CVE_GITHUB_REPO:-}'"
trim_rtsp=$(printf "%s" "${RTSP_LIST_URL:-}" | tr -d '\r\n\t ') ; echo "[DEBUG] RTSP_LIST_URL='${RTSP_LIST_URL:-}'"
[[ -z "$trim_cve" ]] || { echo "[ERROR] CVE_GITHUB_REPO should be empty (offline)"; exit 1; }
[[ -z "$trim_rtsp" ]] || { echo "[ERROR] dynamic_rtsp_url should be empty (offline)"; exit 1; }
[[ "${CVE_CACHE_DIR}" == "data/cves" ]] || { echo "[ERROR] CVE_CACHE_DIR should be data/cves (offline)"; exit 1; }

echo "[OK] env_setup default config OK"

# Restore backup/local state
if [[ -n "$BACKUP" ]]; then
  mv -f "$BACKUP" ./camcfg.json
else
  rm -f ./camcfg.json
fi
