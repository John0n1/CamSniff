###############################################################################
# CamSniff 4.10 – bY https://github.com/John0n1/CamSniff
###############################################################################

# Initial setup and enhanced logging

# Logging function with severity levels
log() {
  local level="$1"
  shift
  local color
  case "$level" in
    INFO) color="\e[32m" ;;   # Green
    WARN) color="\e[33m" ;;   # Yellow
    ERROR) color="\e[31m" ;;  # Red
    *) color="\e[0m" ;;       # Default
  esac
  printf "%b[%s][%s]%b %s\n" "$color" "$(date +'%Y-%m-%d %H:%M:%S')" "$level" "\e[0m" "$*"
}

# Fallbacks for critical tools with enhanced checks
critical_tools=(jq curl nc ffprobe ffplay hydra masscan fping)
for tool in "${critical_tools[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    if [[ "$tool" == "jq" ]]; then
      log INFO "jq not found, installing…"
      apt-get -y install jq >/dev/null 2>&1 || log ERROR "Failed to install jq"
    else
      log WARN "Warning: '$tool' not found. Some features may not work."
    fi
  else
    log INFO "Found required tool: $tool"
  fi
done
