#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Cleanup and exit handling

## This file may be executed or sourced. When sourced, do not exit the caller.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  # Running directly: ensure we are root
  (( EUID == 0 )) || { echo "[-] Please run with sudo"; exit 1; }
fi

# Cleanup function exported for callers
cleanup(){
  echo "[+] Shutting down…"
  pkill -P $$               2>/dev/null || true
  pkill -f __camsniff_player 2>/dev/null || true
  killall avahi-daemon      2>/dev/null || true
}

export -f cleanup

# If executed directly, install traps to run cleanup on exit
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  trap cleanup INT TERM EXIT
  trap 'cleanup; exit 0' SIGHUP
fi

# End of script
