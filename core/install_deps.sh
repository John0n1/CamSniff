#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  return 0
fi

# Skip if dependencies already installed
STAMP_FILE=".deps_installed"

# Detect if running from installed package
SCRIPT_PATH="$0"
if [[ "$SCRIPT_PATH" == *"/usr/share/camsniff/"* ]]; then
  PACKAGE_MODE=1
else
  PACKAGE_MODE=0
fi

# ----------------------------------------
# Logging helpers
# ----------------------------------------
log()          { printf "[\e[32m%s\e[0m] %s\n" "$(date +'%F %T')" "$*"; }
log_install()  { log "Installing $1"; }
log_installed(){ log "Already installed $1"; }
log_build()    { log "Building $1"; }

# ----------------------------------------
# Must be root
# ----------------------------------------
if [[ $EUID -ne 0 ]]; then
  log "ERROR: run as root (sudo)" >&2
  exit 1
fi

# ----------------------------------------
# Check for apt-get availability
# ----------------------------------------
if ! command -v apt-get &>/dev/null; then
  log "ERROR: apt-get is not available. Please install it and try again."
  exit 1
fi

# ----------------------------------------
# Retry function for network-related commands
# ----------------------------------------
retry() {
  local n=1
  local max=5
  local delay=5
  # Usage: retry <command ...>
  # Retries the given command with exponential backoff up to <max> times
  while true; do
    "$@" && return 0
    local rc=$?
    if (( n >= max )); then
      log "Command failed after ${max} attempts: $* (rc=$rc)"
      return $rc
    fi
    log "Retry $n/$max failed (rc=$rc). Sleeping ${delay}s and retrying..."
    sleep "$delay"
    n=$(( n+1 ))
    delay=$(( delay*2 ))
  done
}

# ----------------------------------------
# Apt-get update
# ----------------------------------------
log "Updating package list..."
retry apt-get update -qq

# ----------------------------------------
# Core packages
# ----------------------------------------
if [[ -f "$STAMP_FILE" ]]; then
  log "Dependencies already installed; skipping apt installs."
else
  packages=(
    fping masscan nmap hydra fzf tcpdump tshark arp-scan
  avahi-daemon avahi-discover avahi-utils ffmpeg curl jq snmp
    python3 python3-venv python3-pip python3-opencv
  git rtmpdump build-essential cmake pkgconf autoconf
    automake libtool chafa gobuster medusa onesixtyone
  libssl-dev doxygen
  bluez bluez-tools
  wireless-tools iw network-manager
  )
  for pkg in "${packages[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
      log_installed "$pkg"
    else
      log_install "$pkg"
      retry apt-get install -y -qq "$pkg" || { log "ERROR: Failed to install $pkg"; exit 1; }
    fi
  done

  # ----------------------------------------
  # GitHub CLI + Web Auth
  # ----------------------------------------
  if ! command -v gh &>/dev/null; then
    log_install "GitHub CLI"
    retry curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
      && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
      && printf 'deb [arch=%s signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' \
         "$(dpkg --print-architecture)" \
      | tee /etc/apt/sources.list.d/github-cli.list >/dev/null
    retry apt-get update -qq
    retry apt-get install -y -qq gh
  else
    log_installed "GitHub CLI"
  fi

  if ! gh auth status &>/dev/null; then
    log "Authenticating with GitHub (browser)…"
    gh auth login --web
  else
    log_installed "GitHub authentication"
  fi

  # ----------------------------------------
  # Optional fuzzer installer (for development/advanced use)
  # Note: These are optional tools, not packaged by Debian/Kali
  # ----------------------------------------
  install_fuzzer(){
    local name="${1:-}" repo="${2:-}" bin="${3:-}"
    if [[ -z "$name" || -z "$repo" || -z "$bin" ]]; then
      log "Skipping optional tool (missing arguments)"
      return
    fi
    local dest="/opt/$name"
    if command -v "$name" &>/dev/null; then
      log_installed "$name"
      return
    fi
    
    # Skip installing custom tools when running as installed package
    if (( PACKAGE_MODE )); then
      log "Skipping optional tool $name (package installation mode)"
      return
    fi
    
    log_install "$name"
    rm -rf "$dest"
    if gh repo clone "$repo" "$dest" -- --depth 1 2>/dev/null \
       || git clone --depth 1 "https://github.com/$repo.git" "$dest" &>/dev/null; then
      pushd "$dest" >/dev/null
        if [[ -f Makefile ]]; then
          if make && install -m755 "$bin" "/usr/local/bin/$name"; then
            log_installed "$name"
          else
            log "Build failed for $name, skipping"
          fi
        else
          log "No Makefile in $name, skipping build"
        fi
      popd >/dev/null
    else
      log "Repo not found for $name, skipping"
    fi
  }

  install_fuzzer coap-fuzzer   thingsee/coap-fuzzer   coap-fuzzer
  install_fuzzer rtmp-fuzzer   rtmpdump/rtmpdump       rtmpdump

  # ----------------------------------------
  # Build libcoap client only (docs disabled)
  # Note: This is for CoAP protocol support
  # ----------------------------------------
  if (( !PACKAGE_MODE )); then
    log_build "libcoap"
    rm -rf /opt/libcoap.build
    git clone --depth 1 https://github.com/obgm/libcoap.git /opt/libcoap.build
    mkdir -p /opt/libcoap.build/build
    pushd /opt/libcoap.build/build >/dev/null
      cmake .. \
        -DENABLE_CLIENT_MODE=ON \
        -DENABLE_EXAMPLES=ON \
        -DENABLE_DOCS=OFF \
        -DENABLE_DTLS=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local
      make -j"$(nproc)" coap-client
      install -m755 coap-client /usr/local/bin/
    popd >/dev/null
    log_installed "libcoap (coap-client)"
  else
    log "Skipping libcoap build (package installation mode - use system package if available)"
  fi

  # Mark deps as installed
  touch "$STAMP_FILE"
fi

# ----------------------------------------
# Python venv & deps
# ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.camvenv"
USE_VENV=1
if [[ -d "$VENV_DIR" && -f "$VENV_DIR/bin/activate" ]]; then
  log_installed "Python virtualenv"
else
  log_build "Python virtualenv"
  rm -rf "$VENV_DIR" 2>/dev/null || true
  if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
    log "WARNING: Failed to create virtualenv; proceeding without venv"
    USE_VENV=0
  fi
fi

if (( USE_VENV )) && [[ -f "$VENV_DIR/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
else
  log "Proceeding with system Python packages"
fi

log "Upgrading pip"
if (( USE_VENV )); then
  retry pip install --upgrade pip --quiet
else
  retry pip3 install --upgrade pip --quiet || true
fi

log_install "Python packages"
if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
  if (( USE_VENV )); then
    retry pip install --no-cache-dir -r "$SCRIPT_DIR/requirements.txt" --quiet
  else
    retry pip3 install --user --no-cache-dir -r "$SCRIPT_DIR/requirements.txt" --quiet || true
  fi
else
  if (( USE_VENV )); then
    retry pip install --no-cache-dir wsdiscovery opencv-python requests flask --quiet
  else
    retry pip3 install --user --no-cache-dir wsdiscovery opencv-python requests flask --quiet || true
  fi
fi

log "All done 🎉"
