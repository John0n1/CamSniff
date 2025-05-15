#!/usr/bin/env bash

# Scanning and analysis functions

# Function to run plugins
run_plugins(){
  mkdir -p plugins
  for f in plugins/*.sh; do [[ -x $f ]] && bash "$f" & done
  for p in plugins/*.py; do [[ -x $p ]] && python3 "$p" & done
}

# Function to add stream
add_stream(){ (( ${#STREAMS[@]:-0} < MAX_STREAMS )) && STREAMS["$1"]=1; }

# Function to launch mosaic
launch_mosaic(){
  (( ${#STREAMS[@]:-0} )) || return
  inputs=(); for u in "${!STREAMS[@]:-}"; do inputs+=(-i "$u"); done
  ffmpeg "${inputs[@]}" -filter_complex "xstack=inputs=${#STREAMS[@]:-0}:layout=0*0|w0*0|0*h0|w0*h0" -f matroska - \
    | ffplay -loglevel error -
  unset STREAMS; declare -A STREAMS
}

# Function to take screenshot and analyze
screenshot_and_analyze(){
  u=$1; ip=${u#*://}; ip=${ip%%[:/]*}; out="/tmp/snap_${ip}.jpg"
  ffmpeg -rtsp_transport tcp -i "$u" -frames:v 1 -q:v 2 -y "$out" &>/dev/null && log "[SNAP] $u → $out"
  python3 - <<PY 2>/dev/null
import cv2
img=cv2.imread("$out",0)
_,th=cv2.threshold(img,200,255,cv2.THRESH_BINARY)
cnt=cv2.countNonZero(th)
if cnt>50: print(f"[AI] IR spots detected ({cnt}px)")
PY
}

# Function to check CVE
cve_check(){ grep -iF "$1" "$CVE_DB" 2>/dev/null | head -n3 | xargs -I{} log "[CVE] {}"; }

# Fix discover_onvif syntax
discover_onvif(){
  python3 - <<PY 2>/dev/null
from wsdiscovery.discovery import ThreadedWSDiscovery as WSD
wsd = WSD()
wsd.start()
svcs = wsd.searchServices()
print(f"[ONVIF] {len(svcs)} services")
for s in svcs:
    print("[ONVIF]", s.getXAddrs()[0])
wsd.stop()
PY
}

# Function to discover SSDP
discover_ssdp(){
  echo -ne 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:urn:schemas-upnp-org:device:Basic:1\r\nMAN:"ssdp:discover"\r\nMX:2\r\n\r\n' \
    | nc -u -w2 239.255.255.250 1900 | grep -i LOCATION | head -5 | sed 's/^/ [SSDP] /'
}

# Function to scan HLS
scan_hls(){ for p in live index stream playlist master; do
  url="http://$1:$2/$p.m3u8"
  curl -sfI "$url" | grep -qi 'application/vnd.apple.mpegurl' && { log "[HLS] $url"; add_stream "$url"; return; }
done }

# Function to scan RTSP (enhanced for aggressive scanning)
scan_rtsp(){
  log_debug "Starting RTSP scan for $1:$2"
  for rtsp_path in "${RTSP_PATHS[@]}"; do
    # Replace placeholders in the RTSP path
    u=$(echo "$rtsp_path" | sed "s/{{username}}/admin/g; s/{{password}}/admin/g; s/{{ip_address}}/$1/g; s/{{port}}/$2/g")
    log_debug "Testing RTSP URL: $u"
    ffprobe -v quiet -rtsp_transport tcp -timeout 500000 -i "$u" 2>&1 | grep -q Video: && { 
      log "[RTSP] $u"; 
      add_stream "$u"; 
      return; 
    }
  done

  # Brute-force RTSP with correct port
  log_debug "Starting RTSP brute-force for $1:$2"
  hydra -L "$HYDRA_FILE" -P "$HYDRA_FILE" -s "$2" "$1" rtsp -t "$HYDRA_RATE" &>/dev/null && log "[HYDRA-RTSP] $1:$2"

  # Aggressive RTSP fuzzing
  log "[FUZZ] Starting RTSP fuzzing on $1:$2"
  medusa -h "$1" -n "$2" -M rtsp -t "$MEDUSA_THREADS" -f -F -O "/tmp/rtsp_fuzz_$1_$2.log" &>/dev/null && log "[FUZZ] Results saved to /tmp/rtsp_fuzz_$1_$2.log"
}

# Function to scan HTTP (enhanced for aggressive scanning)
scan_http(){
  for cred in "${HTTP_CREDS[@]}"; do
    IFS=: read u p <<<"$cred"
    url="http://$1:$2/video"
    curl -su "$u:$p" -m3 "$url" 2>/dev/null | grep -q multipart/x-mixed-replace && { log "[MJPEG] $url ($u)"; add_stream "$url"; break; }
  done
  scan_hls "$1" "$2"
  hydra -C "$HYDRA_FILE" -s "$2" http-get://"$1" -t "$HYDRA_RATE" &>/dev/null && log "[HYDRA-HTTP] $1:$2"
  hdr=$(curl -sI "http://$1:$2" | grep -i '^Server:' | cut -d' ' -f2-)
  [[ $hdr ]] && cve_check "$hdr"

  # Aggressive directory brute-forcing
  log "[DIRB] Starting directory brute-force on $1:$2"
  gobuster dir -u "http://$1:$2" -w "$DIRB_WORDLIST" -q -o "/tmp/dirb_$1_$2.log" &>/dev/null && log "[DIRB] Results saved to /tmp/dirb_$1_$2.log"
}

# Function to scan SNMP (enhanced for aggressive scanning)
scan_snmp(){
  for com in "${SNMP_COMM_ARRAY[@]}"; do
    out=$(snmpwalk -v2c -c "$com" -Ovq -t1 -r0 "$1" sysDescr.0 2>/dev/null)
    [[ $out ]] && { log "[SNMP] $1 ($com) → $out"; cve_check "$out"; break; }
  done

  # Aggressive SNMP brute-forcing
  log "[SNMP-BRUTE] Starting SNMP brute-force on $1"
  onesixtyone -c "$SNMP_COMM_FILE" "$1" &>/dev/null && log "[SNMP-BRUTE] Results saved to /tmp/snmp_brute_$1.log"
}

# Function to scan CoAP (enhanced for aggressive scanning)
scan_coap(){
  for p in .well-known/core media stream status; do
    out=$(timeout 3 coap-client -m get -s 2 "coap://$1/$p" 2>/dev/null)
    [[ $out ]] && log "[CoAP] coap://$1/$p → ${out:0:80}"
  done

  # Aggressive CoAP fuzzing
  log "[FUZZ] Starting CoAP fuzzing on $1"
  coap-fuzzer -u "coap://$1" -o "/tmp/coap_fuzz_$1.log" &>/dev/null && log "[FUZZ] Results saved to /tmp/coap_fuzz_$1.log"
}

# Function to scan RTMP (enhanced for aggressive scanning)
scan_rtmp(){
  for p in live/stream live cam play h264; do
    u="rtmp://$1/$p"
    timeout 4 rtmpdump --timeout 2 -r "$u" --stop 1 &>/dev/null && { log "[RTMP] $u"; add_stream "$u"; }
  done

  # Aggressive RTMP fuzzing
  log "[FUZZ] Starting RTMP fuzzing on $1"
  rtmp-fuzzer -u "rtmp://$1" -o "/tmp/rtmp_fuzz_$1.log" &>/dev/null && log "[FUZZ] Results saved to /tmp/rtmp_fuzz_$1.log"
}

# Function to perform a sweep
sweep(){
  log_debug "Starting sweep"
  # Start scan animation in background
  scan_animation &
  local anim_pid=$!
  trap "kill $anim_pid 2>/dev/null" EXIT

  # Suppress fping and arp-scan output
  mapfile -t ALIVE < <(fping -a -g "$SUBNET" 2>/dev/null)
  (( ${#ALIVE[@]} )) || mapfile -t ALIVE < <(arp-scan -l -I "$IF" 2>/dev/null | awk '{print $1}')

  if (( FIRST_RUN )); then
    log "First-run masscan…"
    mapfile -t SCAN < <(masscan "$SUBNET" -p"$PORTS" --rate "$MASSCAN_RATE" -oL - 2>/dev/null | awk '/open/ {print $4":"$2}')
    FIRST_RUN=0
  else
    NEW=()
    for ip in "${ALIVE[@]}"; do
      [[ -z ${HOSTS_SCANNED[$ip]+x} ]] && NEW+=("$ip")
    done
    if ((${#NEW[@]})); then
      log "Masscan new: ${NEW[*]}"
      mapfile -t SCAN < <(masscan "${NEW[@]}" -p"$PORTS" --rate "$MASSCAN_RATE" -oL - 2>/dev/null | awk '/open/ {print $4":"$2}')
    else
      SCAN=()
    fi
  fi

  for e in "${SCAN[@]}"; do
    ip=${e%%:*}; port=${e#*:}
    HOSTS_SCANNED["$ip"]=1
    case $port in
      554|8554|10554|5544|1055) scan_rtsp "$ip" "$port" ;;
      80|8080|8000|81|443)      scan_http "$ip" "$port" ;;
      161)                      scan_snmp "$ip"    ;;
    esac
  done

  discover_onvif; discover_ssdp

  for ip in "${ALIVE[@]}"; do scan_coap "$ip"; done
  for ip in "${ALIVE[@]}"; do scan_rtmp "$ip"; done

  log "Screenshot + AI…"
  for u in "${!STREAMS[@]:-}"; do screenshot_and_analyze "$u"; done

  log "Mosaic…"
  launch_mosaic

  log "TUI…"
  if (( ${#STREAMS[@]:-0} )) && command -v fzf &>/dev/null; then
    printf "%s\n" "${!STREAMS[@]:-}" | fzf --prompt="Select> " | xargs -r -I{} ffplay -loglevel error "{}"
  fi

  run_plugins

  # Stop scan animation and clear line
  kill "$anim_pid" 2>/dev/null
  printf "\r\033[K"
}

# Add trap to terminate scan_animation
scan_animation() {
    local len=8
    local red='\033[31m'
    local reset='\033[0m'
    trap "exit" INT TERM
    while :; do
        for ((i=0; i<len; i++)); do
            local line=""
            for ((j=0; j<len; j++)); do
                if (( j == i )); then
                    line+="${red}~${reset}"
                elif (( j < i )); then
                    line+=" "
                else
                    line+="${red}~${reset}"
                fi
            done
            echo -en "\rScanning... $line"
            sleep 0.1
        done
    done
}
