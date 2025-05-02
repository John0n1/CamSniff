#!/usr/bin/env bash

# Initial setup and logging

# Logging function
log() {
  printf "\e[33m[%s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
}

# Fallbacks for critical tools
for tool in jq curl nc ffprobe ffplay; do
  if ! command -v "$tool" &>/dev/null; then
    if [[ "$tool" == "jq" ]]; then
      log "jq not found, installing…"
      apt-get -y install jq >/dev/null 2>&1
    else
      log "Warning: '$tool' not found. Some features may not work."
    fi
  fi
done
