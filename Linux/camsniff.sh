#!/usr/bin/env bash
###############################################################################
# CamSniff 4.10 – bY https://github.com/John0n1/CamSniff
###############################################################################

# Check if running with bash
if [ -z "$BASH_VERSION" ]; then
  echo "Please run this script with bash, not sh."
  exit 1
fi

set -uo pipefail
IFS=$'\n\t'
declare -A STREAMS        
declare -A HOSTS_SCANNED  
FIRST_RUN=1

#— Pre-split script sourcing
source setup.sh
source install_deps.sh
source env_setup.sh
source scan_analyze.sh
source cleanup.sh

#— Pre-scan prompt
while true; do
  read -rp "Start scanning? (Y/N) " yn
  case $yn in
    [Yy]*) 
      log INFO "Scanning… Ctrl-C to stop"
      (
        sleep 1
      ) &
      pid=$!
      loading_bar "preparing scan" $pid
      wait $pid
      printf "\r\033[K"
      break
      ;;
    [Nn]*) log INFO "Abort—cleanup & delete"; deactivate 2>/dev/null || true; cleanup; rm -rf "$VENV" camcfg.json plugins; exit ;;
    *) echo "Y or N";;
  esac
done

#— Network info & taps
IF=$(ip r | awk '/default/ {print $5;exit}')
SUBNET=$(ip -o -f inet addr show "$IF" | awk '{print $4}')
if [[ -z "$IF" || -z "$SUBNET" ]]; then
  log ERROR "Could not determine network interface or subnet. Exiting."
  exit 1
fi
log INFO "IF=$IF SUBNET=$SUBNET"
avahi-daemon --start 2>/dev/null || true
tcpdump -i "$IF" -l -n -q '(arp or (udp port 67 or udp port 68))' >/dev/null 2>&1 &
tcpdump -i "$IF" -l -n -q '(udp port 5353 or udp port 3702)' >/dev/null 2>&1 &
tshark -i "$IF" -l -Y 'rtsp||http||coap||mqtt||rtmp' -T fields -e ip.src -e tcp.port -e udp.port >/dev/null 2>&1 &

#— RTSP list & creds
log INFO "Fetching RTSP paths…"
if curl -sfL "$RTSP_LIST_URL" -o /tmp/rtsp_paths.txt; then
  mapfile -t RTSP_PATHS < /tmp/rtsp_paths.txt
else
  RTSP_PATHS=(live.sdp h264 stream1 video)
fi
HTTP_CREDS=(admin:admin admin:123456 admin:1234 admin:password root:root root:123456 root:toor user:user guest:guest :admin admin:)
HYDRA_FILE=/tmp/.hydra_creds.txt
printf "%s\n" "${HTTP_CREDS[@]}" > "$HYDRA_FILE"

while true; do
  log INFO "===== SWEEP $(date '+%F %T') ====="
  sweep
  log INFO "Sleeping ${SS}s…"
  sleep "$SS"
done
