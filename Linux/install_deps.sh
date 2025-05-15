#!/usr/bin/env bash

# Dependency installation and virtual environment setup with enhanced error handling and logging

# Function to show loading animation
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

# Install dependencies
log INFO "Installing deps…"
apt-get -qq update || { log ERROR "apt-get update failed"; exit 1; }

deps=(fping masscan nmap hydra fzf tcpdump tshark arp-scan avahi-utils \
      ffmpeg curl jq snmp snmp-mibs-downloader python3 python3-venv python3-pip \
      python3-opencv git rtmpdump build-essential cmake pkg-config autoconf automake libtool chafa)

# Function to install a single dependency with retry mechanism
install_dependency() {
  local dep="$1"
  local retries=3
  local count=0
  while (( count < retries )); do
    if ! dpkg -l | grep -qw "$dep"; then
      (
        DEBIAN_FRONTEND=noninteractive apt-get -y install "$dep" >/dev/null 2>&1
      ) &
      pid=$!
      loading_bar "installing $dep" $pid
      wait $pid
      if dpkg -l | grep -qw "$dep"; then
        log INFO "Installed $dep"
        return 0
      else
        log ERROR "Failed to install $dep, retrying... ($((count+1))/$retries)"
        ((count++))
      fi
    else
      log INFO "$dep already installed"
      return 0
    fi
  done
  log ERROR "Failed to install $dep after $retries attempts"
  return 1
}

# Export the function to be used by xargs
export -f install_dependency
export -f loading_bar
export -f log

# Use xargs to install dependencies concurrently
echo "${deps[@]}" | xargs -n 1 -P 4 -I {} bash -c 'install_dependency "$@"' _ {}

# Build libcoap if not found
if ! command -v coap-client &>/dev/null; then
  log INFO "Building libcoap…"
  tmp=/opt/libcoap.build
  (
    rm -rf "$tmp"
    git clone --depth 1 https://github.com/obgm/libcoap.git "$tmp" >/dev/null
    cmake -S "$tmp" -B "$tmp/build" -DENABLE_CLIENT=ON -DENABLE_DTLS=OFF -DENABLE_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "$tmp/build" --target coap-client -j"$(nproc)" >/dev/null
    # Correct path for coap-client binary
    if [[ -f "$tmp/build/client/coap-client" ]]; then
      install -m755 "$tmp/build/client/coap-client" /usr/local/bin/
    elif [[ -f "$tmp/build/coap-client" ]]; then
      install -m755 "$tmp/build/coap-client" /usr/local/bin/
    else
      log WARN "coap-client binary not found after build"
      exit 1
    fi
  ) &
  pid=$!
  loading_bar "building libcoap" $pid
  wait $pid
  log INFO "Built libcoap"
fi

# Create Python virtual environment using pipenv
VENV=".camvenv"
if [[ ! -d $VENV ]]; then
  (
    pipenv --python 3
  ) &
  pid=$!
  loading_bar "creating python venv" $pid
  wait $pid
  if [[ -d $VENV ]]; then
    log INFO "Created venv"
  else
    log ERROR "Failed to create python venv"
    exit 1
  fi
fi

# Activate the virtual environment
pipenv shell

# Install Python dependencies using pipenv
(
  pipenv install wsdiscovery opencv-python
) &
pid=$!
loading_bar "installing python deps" $pid
wait $pid
log INFO "Installed python deps"
