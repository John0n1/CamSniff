#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Initial setup and logging

_SETUP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$_SETUP_SCRIPT_DIR")"

# Function to sync python requirements into existing venv (idempotent)
_camsniff_requirements_sync(){
  local req_file="$ROOT_DIR/requirements.txt" hash_file="$_SETUP_SCRIPT_DIR/.req_hash"
  [[ -f "$req_file" ]] || return 0
  local new_hash
  new_hash=$(sha256sum "$req_file" 2>/dev/null | awk '{print $1}') || return 0
  local old_hash="$(cat "$hash_file" 2>/dev/null || echo)"
  if [[ "$new_hash" != "$old_hash" ]]; then
    # Skip if explicitly disabled
    if [[ "${CAMSNIFF_SKIP_PIP:-0}" == "1" ]]; then
      return 0
    fi
    log "requirements.txt change detected – installing (hash $new_hash)"
    local venv_dir="$_SETUP_SCRIPT_DIR/.camvenv"
    if [[ -d "$venv_dir" && -f "$venv_dir/bin/activate" ]]; then
      # shellcheck disable=SC1091
      source "$venv_dir/bin/activate" || true
      (pip install --no-cache-dir -r "$req_file" --quiet && echo "$new_hash" > "$hash_file") || log "WARNING: pip install may have failed"
    else
      (pip3 install --user --no-cache-dir -r "$req_file" --quiet && echo "$new_hash" > "$hash_file") || log "WARNING: pip3 user install may have failed"
    fi
  fi
}

if [[ -n "${_CAMSNIFF_SETUP_RAN:-}" ]]; then
  # Already sourced once; still attempt requirement sync (cheap)
  _camsniff_requirements_sync
  return 0 2>/dev/null || exit 0
fi
_CAMSNIFF_SETUP_RAN=1

# Logging function (only if interactive terminal)
log() {
  if [[ -t 1 ]]; then
    printf "\e[33m[%s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"
  else
    printf "[setup %s] %s\n" "$(date +'%H:%M:%S')" "$*"
  fi
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

export CAMSNIFF_OUTPUT="${CAMSNIFF_OUTPUT:-$ROOT_DIR/output}"

# Perform requirement sync at end of setup actions (silent if no change)
_camsniff_requirements_sync || true
