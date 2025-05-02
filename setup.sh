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
