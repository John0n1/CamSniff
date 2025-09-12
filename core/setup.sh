#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Initial setup and logging

# Logging function
log() {
  printf "\e[33m[%s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
}

# Simple loading bar: takes a message and a PID, prints dots until the PID exits
loading_bar(){
  local msg="$1" pid="$2" delay=0.2
  printf "%s" "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    printf "."
    sleep "$delay"
  done
  printf "\n"
}

# Fallbacks for critical tools
for tool in jq curl nc ffmpeg ffplay; do
  if ! command -v "$tool" &>/dev/null; then
    if [[ "$EUID" -ne 0 ]]; then
      log "Warning: '$tool' not found. Please install it as root (e.g. sudo apt-get install $tool)"
    else
      log "$tool not found, installing..."
      apt-get -y install "$tool" >/dev/null 2>&1 || { log "ERROR: Failed to install $tool"; exit 1; }
    fi
  fi
done
