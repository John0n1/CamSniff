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
trap cleanup INT TERM EXIT

# Loading animation function
loading_bar() {
  local msg="$1"
  local pid
  local spin='-\|/'
  local i=0
  printf "\r%s" "$msg"
  while kill -0 "$2" 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\r%s %s" "$msg" "${spin:$i:1}"
    sleep 0.1
  done
  printf "\r\033[K" # clear line
}
