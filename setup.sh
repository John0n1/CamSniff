#!/usr/bin/env bash

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
for tool in jq curl nc ffprobe ffplay; do
  if ! command -v "$tool" &>/dev/null; then
    if [[ "$tool" == "jq" ]]; then
      log "jq not found, installing…"
      apt-get -y install jq >/dev/null 2>&1 || { log "ERROR: Failed to install jq"; exit 1; }
    else
      log "Warning: '$tool' not found. Installing it now…"
      apt-get -y install "$tool" >/dev/null 2>&1 || { log "ERROR: Failed to install $tool"; exit 1; }
    fi
  fi
done
