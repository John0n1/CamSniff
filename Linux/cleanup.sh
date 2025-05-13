#!/usr/bin/env bash

# Cleanup and exit handling with enhanced logging and reliability

# Ensure the script is run as root
(( EUID == 0 )) || { echo "[-] sudo please"; exit 1; }

# Cleanup function
cleanup(){
  log INFO "Shutting down…"
  pkill -P $$               2>/dev/null || log WARN "No child processes to kill"
  pkill -f __camsniff_player 2>/dev/null || log WARN "No __camsniff_player processes to kill"
  if killall avahi-daemon 2>/dev/null; then
    log INFO "avahi-daemon terminated"
  else
    log WARN "avahi-daemon not running"
  fi
}

# Trap signals and call cleanup function
trap cleanup INT TERM EXIT
