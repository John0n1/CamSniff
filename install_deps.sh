#!/usr/bin/env bash

# Dependency installation and virtual environment setup

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
log "Installing deps…"
apt-get -qq update

deps=(fping masscan nmap hydra fzf tcpdump tshark arp-scan avahi-utils \
      ffmpeg curl jq snmp snmp-mibs-downloader python3 python3-venv python3-pip \
      python3-opencv git rtmpdump build-essential cmake pkg-config autoconf automake libtool chafa)
for d in "${deps[@]}"; do
  if ! dpkg -l | grep -qw "$d"; then
    (
      DEBIAN_FRONTEND=noninteractive apt-get -y install "$d" >/dev/null 2>&1
    ) &
    pid=$!
    loading_bar "installing $d" $pid
    wait $pid
    printf "\r\033[K" # clear line after install
    log "Installed $d"
  fi
done

# Build libcoap if not found
if ! command -v coap-client &>/dev/null; then
  log "Building libcoap…"
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
      log "coap-client go for launch"
    fi
  ) &
  pid=$!
  loading_bar "building libcoap" $pid
  wait $pid
  printf "\r\033[K"
  log "Built libcoap"
fi

# Create Python virtual environment
VENV=".camvenv"
if [[ ! -d $VENV ]]; then
  (
    python3 -m venv "$VENV"
  ) &
  pid=$!
  loading_bar "creating python venv" $pid
  wait $pid
  printf "\r\033[K"
  log "Created venv"
fi
# shellcheck source=/dev/null
source "$VENV/bin/activate"

# Fallback: ensure pip exists in venv
if ! command -v pip &>/dev/null; then
  log "pip not found in venv, bootstrapping…"
  curl -sS https://bootstrap.pypa.io/get-pip.py | python3
fi

# Upgrade pip
(
  pip install --upgrade pip >/dev/null
) &
pid=$!
loading_bar "upgrading pip" $pid
wait $pid
printf "\r\033[K"
log "Upgraded pip"

# Install Python dependencies
(
  pip install --no-cache-dir wsdiscovery opencv-python >/dev/null
) &
pid=$!
loading_bar "installing python deps" $pid
wait $pid
printf "\r\033[K"
log "Installed python deps"
