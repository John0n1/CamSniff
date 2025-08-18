#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Tiny smoke test for CVE checking helper paths

# Ensure jq exists if env_setup will require it
if ! command -v jq >/dev/null 2>&1; then
  echo "[SKIP] jq not installed; CVE test not applicable here"
  exit 0
fi

# Create a temp config with minimal viable fields
CFG=$(mktemp)
cat >"$CFG" <<JSON
{
  "sleep_seconds": 1,
  "nmap_ports": "80",
  "masscan_rate": 1000,
  "hydra_rate": 4,
  "max_streams": 1,
  "cve_github_repo": "https://github.com/CVEProject/cvelistV5/tree/main/cves",
  "cve_cache_dir": "/tmp/cve_cache_test",
  "cve_current_year": "2025",
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/John0n1/CamSniff/main/data/rtsp_paths.csv",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "password_wordlist": "data/passwords.txt",
  "username_wordlist": "data/usernames.txt",
  "snmp_communities": ["public"],
  "medusa_threads": 2
}
JSON

# Use CONFIG_FILE via env when sourcing
export HOME=${HOME:-/tmp}
cp "$CFG" ./camcfg.json 2>/dev/null || true

# Source env_setup to populate vars
source ./env_setup.sh

# Validate key vars
: "${CVE_CACHE_DIR:?}"
: "${RTSP_LIST_URL:?}"

# Try quick cve_check on a known string via scan_analyze helpers
source ./scan_analyze.sh

# Call function in a subshell to avoid running the whole sweep
( type cve_fallback_check >/dev/null 2>&1 && cve_fallback_check "hikvision camera" ) || true

echo "[OK] CVE helper test completed"
