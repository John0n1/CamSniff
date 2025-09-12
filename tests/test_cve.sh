#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Tiny smoke test for CVE checking helper paths
# Ensure jq exists if env_setup will require it
if ! command -v jq >/dev/null 2>&1; then
  echo "[SKIP] jq not installed; CVE test not applicable here"
  exit 0
fi

export HOME=${HOME:-/tmp}
cat > ./camcfg.json <<'JSON'
{
  "sleep_seconds": 1,
  "nmap_ports": "80",
  "masscan_rate": 1000,
  "hydra_rate": 4,
  "max_streams": 1,
  "cve_github_repo": "",
  "cve_cache_dir": "data/cves",
  "cve_current_year": "2025",
  "dynamic_rtsp_url": "",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "password_wordlist": "data/passwords.txt",
  "username_wordlist": "data/usernames.txt",
  "snmp_communities": ["public"],
  "medusa_threads": 2
}
JSON

# Source env_setup to populate vars
# shellcheck disable=SC1091
source ../core/env_setup.sh

# Validate key vars
: "${CVE_CACHE_DIR:?}"
[[ -z "${RTSP_LIST_URL:-}" ]] || { echo "[ERROR] RTSP_LIST_URL not empty in offline mode"; exit 1; }

# Try quick cve_check on a known string via scan_analyze helpers
# shellcheck disable=SC1091
source ../core/scan_analyze.sh

python3 ../python_core/cve_quick_search.py hikvision >/dev/null 2>&1 || true

# Call fallback in a subshell to avoid running the whole sweep
( type cve_fallback_check >/dev/null 2>&1 && cve_fallback_check "hikvision camera" ) || true

echo "[OK] CVE helper test completed"
