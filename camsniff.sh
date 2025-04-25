#!/usr/bin/env bash
###############################################################################
# CamSniff 4.10 – bY https://github.com/John0n1/CamSniff
###############################################################################
set -uo pipefail
IFS=$'\n\t'
declare -A STREAMS        
declare -A HOSTS_SCANNED  
FIRST_RUN=1

#— Logging
log(){ printf "\e[33m[%s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"; }

#— Config
read -r -d '' DEFAULT_CFG <<'JSON'
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/usr/share/cve/cve-2025.json",
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/maaaaz/michelle/master/rtsp.txt"
}
JSON
[[ -f camcfg.json ]] || printf '%s\n' "$DEFAULT_CFG" > camcfg.json
JQ(){ command jq "$@"; }
SS=$(JQ -r '.sleep_seconds' camcfg.json)
PORTS=$(JQ -r '.nmap_ports'    camcfg.json)
MASSCAN_RATE=$(JQ -r '.masscan_rate' camcfg.json)
HYDRA_RATE=$(JQ -r '.hydra_rate'   camcfg.json)
MAX_STREAMS=$(JQ -r '.max_streams' camcfg.json)
CVE_DB=$(JQ -r '.cve_db'          camcfg.json)
RTSP_LIST_URL=$(JQ -r '.dynamic_rtsp_url' camcfg.json)

#— Cleanup
(( EUID == 0 )) || { echo "[-] sudo please"; exit 1; }
cleanup(){
  log "Shutting down…"
  pkill -P $$               2>/dev/null || true
  pkill -f __camsniff_player 2>/dev/null || true
  killall avahi-daemon      2>/dev/null || true
}
trap cleanup INT TERM EXIT

#— Deps & venv
log "Installing deps…"
apt-get -qq update
deps=(fping masscan nmap hydra fzf tcpdump tshark arp-scan avahi-utils \
      ffmpeg curl jq snmp snmp-mibs-downloader python3 python3-venv python3-pip \
      python3-opencv git rtmpdump build-essential cmake pkg-config autoconf automake libtool chafa)
for d in "${deps[@]}"; do
  dpkg -l | grep -qw "$d" || DEBIAN_FRONTEND=noninteractive apt-get -y install "$d" >/dev/null
done
if ! command -v coap-client &>/dev/null; then
  log "Building libcoap…"
  tmp=/opt/libcoap.build
  git clone --depth 1 https://github.com/obgm/libcoap.git "$tmp" >/dev/null
  cmake -S "$tmp" -B "$tmp/build" -DENABLE_CLIENT=ON -DENABLE_DTLS=OFF -DENABLE_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "$tmp/build" --target coap-client -j"$(nproc)" >/dev/null
  install -m755 "$tmp/build/coap-client" /usr/local/bin/
fi

VENV=".camvenv"
if [[ ! -d $VENV ]]; then
  log "Creating venv…"
  python3 -m venv "$VENV"
fi
# shellcheck source=/dev/null
source "$VENV/bin/activate"
pip install --upgrade pip >/dev/null
pip install --no-cache-dir wsdiscovery opencv-python >/dev/null

#— Pre-scan prompt
while true; do
  read -rp "Start scanning? (Y/N) " yn
  case $yn in
    [Yy]*) log "Scanning… Ctrl-C to stop"; break ;;
    [Nn]*) log "Abort—cleanup & delete"; deactivate 2>/dev/null || true; cleanup; rm -rf "$VENV" camcfg.json plugins; exit ;;
    *) echo "Y or N";;
  esac
done

#— Network info & taps
IF=$(ip r | awk '/default/ {print $5;exit}')
SUBNET=$(ip -o -f inet addr show "$IF" | awk '{print $4}')
log "IF=$IF SUBNET=$SUBNET"
avahi-daemon --start 2>/dev/null || true
tcpdump -i "$IF" -l -n -q '(arp or (udp port 67 or udp port 68))' &
tcpdump -i "$IF" -l -n -q '(udp port 5353 or udp port 3702)' &
tshark -i "$IF" -l -Y 'rtsp||http||coap||mqtt||rtmp' -T fields -e ip.src -e tcp.port -e udp.port &

#— RTSP list & creds
log "Fetching RTSP paths…"
if curl -sfL "$RTSP_LIST_URL" -o /tmp/rtsp_paths.txt; then
  mapfile -t RTSP_PATHS < /tmp/rtsp_paths.txt
else
  RTSP_PATHS=(live.sdp h264 stream1 video)
fi
HTTP_CREDS=(admin:admin admin:123456 admin:1234 admin:password root:root root:123456 root:toor user:user guest:guest :admin admin:)
HYDRA_FILE=/tmp/.hydra_creds.txt
printf "%s\n" "${HTTP_CREDS[@]}" > "$HYDRA_FILE"

run_plugins(){
  mkdir -p plugins
  for f in plugins/*.sh; do [[ -x $f ]] && bash "$f" & done
  for p in plugins/*.py; do [[ -x $p ]] && python3 "$p" & done
}

add_stream(){ (( ${#STREAMS[@]:-0} < MAX_STREAMS )) && STREAMS["$1"]=1; }
launch_mosaic(){
  (( ${#STREAMS[@]:-0} )) || return
  inputs=(); for u in "${!STREAMS[@]:-}"; do inputs+=(-i "$u"); done
  ffmpeg "${inputs[@]}" -filter_complex "xstack=inputs=${#STREAMS[@]:-0}:layout=0*0|w0*0|0*h0|w0*h0" -f matroska - \
    | ffplay -loglevel error -
  unset STREAMS; declare -A STREAMS
}

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

cve_check(){ grep -iF "$1" "$CVE_DB" 2>/dev/null | head -n3 | xargs -I{} log "[CVE] {}"; }

discover_onvif(){
  python3 - <<PY 2>/dev/null
from wsdiscovery.discovery import ThreadedWSDiscovery as WSD
wsd=WSD(); wsd.start(); svcs=wsd.searchServices()
print(f"[ONVIF] {len(svcs)} services")
for s in svcs: print("[ONVIF]",s.getXAddrs()[0])
wsd.stop()
PY
}
discover_ssdp(){
  echo -ne 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:urn:schemas-upnp-org:device:Basic:1\r\nMAN:"ssdp:discover"\r\nMX:2\r\n\r\n' \
    | nc -u -w2 239.255.255.250 1900 | grep -i LOCATION | head -5 | sed 's/^/ [SSDP] /'
}

scan_hls(){ for p in live index stream playlist master; do
  url="http://$1:$2/$p.m3u8"
  curl -sfI "$url" | grep -qi 'application/vnd.apple.mpegurl' && { log "[HLS] $url"; add_stream "$url"; return; }
done }

scan_rtsp(){ for p in "${RTSP_PATHS[@]}"; do
  u="rtsp://$1:$2/$p"
  ffprobe -v quiet -rtsp_transport tcp -timeout 500000 -i "$u" 2>&1 | grep -q Video: && { log "[RTSP] $u"; add_stream "$u"; return; }
done
hydra -L "$HYDRA_FILE" -P "$HYDRA_FILE" "$1" rtsp &>/dev/null && log "[HYDRA-RTSP] $1:$2"; }

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
}

scan_snmp(){ for com in public private camera admin; do
  out=$(snmpwalk -v2c -c "$com" -Ovq -t1 -r0 "$1" sysDescr.0 2>/dev/null)
  [[ $out ]] && { log "[SNMP] $1 ($com) → $out"; cve_check "$out"; break; }
done }

scan_coap(){ for p in .well-known/core media stream status; do
  out=$(timeout 3 coap-client -m get -s 2 "coap://$1/$p" 2>/dev/null)
  [[ $out ]] && log "[CoAP] coap://$1/$p → ${out:0:80}"
done }

scan_rtmp(){ for p in live/stream live cam play h264; do
  u="rtmp://$1/$p"
  timeout 4 rtmpdump --timeout 2 -r "$u" --stop 1 &>/dev/null && { log "[RTMP] $u"; add_stream "$u"; }
done }

sweep(){
  log "Discovering alive hosts…"
  mapfile -t ALIVE < <(fping -a -g "$SUBNET" 2>/dev/null)
  (( ${#ALIVE[@]} )) || mapfile -t ALIVE < <(arp-scan -l -I "$IF" | awk '{print $1}')

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
}

while true; do
  log "===== SWEEP $(date '+%F %T') ====="
  sweep
  log "Sleeping ${SS}s…"
  sleep "$SS"
done
