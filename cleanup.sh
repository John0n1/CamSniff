#!/usr/bin/env bash

# Cleanup and exit handling

# Ensure the script is run as root
(( EUID == 0 )) || { echo "[-] sudo please"; exit 1; }

# Cleanup function
cleanup(){
  log "Shutting down…"
  pkill -P $$               2>/dev/null || true
  pkill -f __camsniff_player 2>/dev/null || true
  killall avahi-daemon      2>/dev/null || true
}

# Trap signals and call cleanup function
trap cleanup INT TERM EXIT
