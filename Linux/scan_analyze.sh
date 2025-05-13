#!/usr/bin/env bash

# Scanning and analysis functions with enhanced error handling, extended features, and reporting

# Function to run plugins with concurrency control and error isolation
run_plugins(){
  mkdir -p plugins
  for f in plugins/*.sh; do
    if [[ -x $f ]]; then
      bash "$f" &
      pids+=($!)
    fi
  done
  for p in plugins/*.py; do
    if [[ -x $p ]]; then
      python3 "$p" &
      pids+=($!)
    fi
  done
  # Wait for all plugins to finish
  for pid in "${pids[@]:-}"; do
    wait "$pid" || log WARN "Plugin process $pid exited with error"
  done
  unset pids
}

# Function to add stream with max streams check
add_stream(){ 
  if (( ${#STREAMS[@]:-0} < MAX_STREAMS )); then 
    STREAMS["$1"]=1
  fi
}

# Function to launch mosaic with error handling
launch_mosaic(){
  (( ${#STREAMS[@]:-0} )) || return
  inputs=()
  for u in "${!STREAMS[@]:-}"; do inputs+=(-i "$u"); done
  ffmpeg "${inputs[@]}" -filter_complex "xstack=inputs=${#STREAMS[@]:-0}:layout=0*0|w0*0|0*h0|w0*h0" -f matroska - 2>/dev/null \
    | ffplay -loglevel error - 2>/dev/null
  unset STREAMS
  declare -A STREAMS
}

# Function to take screenshot and analyze with error handling
screenshot_and_analyze(){
  u=$1
  ip=${u#*://}
  ip=${ip%%[:/]*}
  out="/tmp/snap_${ip}.jpg"
  if ffmpeg -rtsp_transport tcp -i "$u" -frames:v 1 -q:v 2 -y "$out" &>/dev/null; then
    log INFO "[SNAP] $u → $out"
    python3 - <<PY 2>/dev/null
import cv2
img=cv2.imread("$out",0)
_,th=cv2.threshold(img,200,255,cv2.THRESH_BINARY)
cnt=cv2.countNonZero(th)
if cnt>50: print(f"[AI] IR spots detected ({cnt}px)")
PY
  else
    log WARN "Failed to take screenshot from $u"
  fi
}

# Function to check CVE with enhanced output
cve_check(){ 
  if [[ -f "$CVE_DB" ]]; then
    grep -iF "$1" "$CVE_DB" 2>/dev/null | head -n10 | while read -r line; do
      log INFO "[CVE] $line"
    done
  else
    log WARN "CVE DB not found at $CVE_DB"
  fi
}

# Function to discover ONVIF with error handling
discover_onvif(){
  python3 - <<PY 2>/dev/null
from wsdiscovery.discovery import ThreadedWSDiscovery as WSD
wsd=WSD()
wsd.start()
svcs=wsd.searchServices()
print(f"[ONVIF] {len(svcs)} services")
for s in svcs:
  print("[ONVIF]", s.getXAddrs()[0])
wsd.stop()
PY
}

# Function to discover SSDP with error handling
discover_ssdp(){
  echo -ne 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:urn:schemas-upnp-org:device:Basic:1\r\nMAN:"ssdp:discover"\r\nMX:2\r\n\r\n' \
    | nc -u -w2 239.255.255.250 1900 2>/dev/null | grep -i LOCATION | head -5 | sed 's/^/ [SSDP] /'
}

# Function to scan HLS with error handling
scan_hls(){ 
  for p in live index stream playlist master; do
    url="http://$1:$2/$p.m3u8"
    if curl -sfI "$url" 2>/dev/null | grep -qi 'application/vnd.apple.mpegurl'; then
      log INFO "[HLS] $url"
      add_stream "$url"
      return
    fi
  done
}

# Function to scan RTSP with error handling and hydra check
scan_rtsp(){ 
  for p in "${RTSP_PATHS[@]}"; do
    u="rtsp://$1:$2/$p"
    if ffprobe -v quiet -rtsp_transport tcp -timeout 500000 -i "$u" 2>&1 | grep -q Video:; then
      log INFO "[RTSP] $u"
      add_stream "$u"
      return
    fi
  done
  if hydra -L "$HYDRA_FILE" -P "$HYDRA_FILE" "$1" rtsp &>/dev/null; then
    log INFO "[HYDRA-RTSP] $1:$2"
  fi
}

# Function to scan HTTP with error handling and hydra check
scan_http(){
  for cred in "${HTTP_CREDS[@]}"; do
    IFS=: read -r u p <<<"$cred"
    url="http://$1:$2/video"
    if curl -su "$u:$p" -m3 "$url" 2>/dev/null | grep -q multipart/x-mixed-replace; then
      log INFO "[MJPEG] $url ($u)"
      add_stream "$url"
      break
    fi
  done
  scan_hls "$1" "$2"
  if hydra -C "$HYDRA_FILE" -s "$2" http-get://"$1" -t "$HYDRA_RATE" &>/dev/null; then
    log INFO "[HYDRA-HTTP] $1:$2"
  fi
  hdr=$(curl -sI "http://$1:$2" 2>/dev/null | grep -i '^Server:' | cut -d' ' -f2-)
  if [[ $hdr ]]; then
    cve_check "$hdr"
  fi
}

# Function to scan SNMP with error handling
scan_snmp(){ 
  for com in public private camera admin; do
    out=$(snmpwalk -v2c -c "$com" -Ovq -t1 -r0 "$1" sysDescr.0 2>/dev/null)
    if [[ $out ]]; then
      log INFO "[SNMP] $1 ($com) → $out"
      cve_check "$out"
      break
    fi
  done
}

# Function to scan CoAP with error handling
scan_coap(){ 
  for p in .well-known/core media stream status; do
    out=$(timeout 3 coap-client -m get -s 2 "coap://$1/$p" 2>/dev/null)
    if [[ $out ]]; then
      log INFO "[CoAP] coap://$1/$p → ${out:0:80}"
    fi
  done
}

# Function to scan RTMP with error handling
scan_rtmp(){ 
  for p in live/stream live cam play h264; do
    u="rtmp://$1/$p"
    if timeout 4 rtmpdump --timeout 2 -r "$u" --stop 1 &>/dev/null; then
      log INFO "[RTMP] $u"
      add_stream "$u"
    fi
  done
}

# Function to perform a sweep with enhanced error handling and reporting
sweep(){
  scan_animation &
  local anim_pid=$!
  mapfile -t ALIVE < <(fping -a -g "$SUBNET" 2>/dev/null)
  if (( ${#ALIVE[@]} == 0 )); then
    mapfile -t ALIVE < <(arp-scan -l -I "$IF" 2>/dev/null | awk '{print $1}')
  fi

  if (( FIRST_RUN )); then
    log INFO "First-run masscan…"
    mapfile -t SCAN < <(masscan "$SUBNET" -p"$PORTS" --rate "$MASSCAN_RATE" -oL - 2>/dev/null | awk '/open/ {print $4":"$2}')
    FIRST_RUN=0
  else
    NEW=()
    for ip in "${ALIVE[@]}"; do
      if [[ -z ${HOSTS_SCANNED[$ip]+x} ]]; then
        NEW+=("$ip")
      fi
    done
    if ((${#NEW[@]})); then
      log INFO "Masscan new: ${NEW[*]}"
      mapfile -t SCAN < <(masscan "${NEW[@]}" -p"$PORTS" --rate "$MASSCAN_RATE" -oL - 2>/dev/null | awk '/open/ {print $4":"$2}')
    else
      SCAN=()
    fi
  fi

  for e in "${SCAN[@]}"; do
    ip=${e%%:*}
    port=${e#*:}
    HOSTS_SCANNED["$ip"]=1
    case $port in
      554|8554|10554|5544|1055) scan_rtsp "$ip" "$port" ;;
      80|8080|8000|81|443)      scan_http "$ip" "$port" ;;
      161)                      scan_snmp "$ip"    ;;
    esac
  done

  discover_onvif
  discover_ssdp

  for ip in "${ALIVE[@]}"; do scan_coap "$ip"; done
  for ip in "${ALIVE[@]}"; do scan_rtmp "$ip"; done

  log INFO "Screenshot + AI…"
  for u in "${!STREAMS[@]:-}"; do screenshot_and_analyze "$u"; done

  log INFO "Mosaic…"
  launch_mosaic

  log INFO "TUI…"
  if (( ${#STREAMS[@]:-0} )) && command -v fzf &>/dev/null; then
    printf "%s\n" "${!STREAMS[@]:-}" | fzf --prompt="Select> " | xargs -r -I{} ffplay -loglevel error "{}"
  fi

  run_plugins

  # Stop scan animation and clear line
  kill "$anim_pid" 2>/dev/null
  printf "\r\033[K"

  # Generate scan summary report
  {
    echo "===== SWEEP $(date '+%F %T') ====="
    echo "Hosts scanned: ${#HOSTS_SCANNED[@]}"
    echo "Streams found: ${#STREAMS[@]:-0}"
    echo "Active streams:"
    for stream in "${!STREAMS[@]:-}"; do
      echo " - $stream"
    done
  } >> "$REPORT_FILE"
}

# Enhanced scan animation with graceful interruption
scan_animation() {
  local len=8
  local red='\033[31m'
  local reset='\033[0m'
  trap 'printf "\r\033[K"; exit' INT TERM EXIT
  while :; do
    for ((i=0; i<len; i++)); do
      local line=""
      for ((j=0; j<len; j++)); do
        if (( j == i )); then
          line+="${red}●${reset}"
        elif (( j < i )); then
          line+=" "
        else
          line+="${red}●${reset}"
        fi
      done
      echo -en "\rScanning... $line"
      sleep 0.1
    done
  done
}
