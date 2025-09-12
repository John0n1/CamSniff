#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

YELLOW='\033[33m'; GREEN='\033[32m'; RED='\033[31m'; RESET='\033[0m'

ok(){ echo -e "${GREEN}[OK]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${RESET} $*"; }
err(){ echo -e "${RED}[ERR]${RESET} $*"; }

# Basic environment
echo "CamSniff Doctor"
echo "----------------"

# OS / tools detection
if command -v apt-get >/dev/null 2>&1; then
  ok "apt-get present"
else
  warn "apt-get not found (non-Debian env). Some installs may fail."
fi

# Required baseline tools
req_tools=(jq curl ffmpeg python3)
missing=()
for t in "${req_tools[@]}"; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done
if (( ${#missing[@]} )); then
  err "Missing required tools: ${missing[*]}"
else
  ok "Core tools present: ${req_tools[*]}"
fi

# Network tools (optional but recommended)
net_tools=(fping masscan nmap hydra tshark arp-scan avahi-browse)
missing_net=()
for t in "${net_tools[@]}"; do
  command -v "$t" >/dev/null 2>&1 || missing_net+=("$t")
done
if (( ${#missing_net[@]} )); then
  warn "Missing recommended tools: ${missing_net[*]}"
else
  ok "All recommended network tools present"
fi

# Python venv and packages
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.camvenv"
if [[ -d "$VENV_DIR" ]]; then
  source "$VENV_DIR/bin/activate"
  ok "Virtualenv found"
  # Check packages
  py_missing=()
  for pkg in wsdiscovery opencv-python requests flask; do
    python3 -c "import $pkg" >/dev/null 2>&1 || py_missing+=("$pkg")
  done
  if (( ${#py_missing[@]} )); then
    warn "Missing Python packages in venv: ${py_missing[*]}"
  else
    ok "Python deps available in venv"
  fi
else
  warn "Virtualenv not found at $VENV_DIR"
fi

# Capabilities / permissions
if [[ $EUID -ne 0 ]]; then
  warn "Not running as root; some scans need sudo"
else
  ok "Running as root"
fi

# Network interface/subnet detection
IF=$(ip r | awk '/default/ {print $5; exit}')
SUBNET=$(ip -o -f inet addr show "$IF" 2>/dev/null | awk '{print $4}')
if [[ -n "${IF:-}" && -n "${SUBNET:-}" ]]; then
  ok "Detected interface $IF with subnet $SUBNET"
else
  warn "Could not detect default interface/subnet"
fi

# Data directories
OUT="$SCRIPT_DIR/output"
mkdir -p "$OUT"/{logs,reports,screenshots} 2>/dev/null || true
ok "Output directories look good at $OUT"

echo "\nDiagnostics completed."