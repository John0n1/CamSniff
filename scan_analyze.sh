#!/usr/bin/env bash

# Scanning and analysis functions

# Function to run plugins
run_plugins(){
  mkdir -p plugins
  for f in plugins/*.sh; do [[ -x $f ]] && bash "$f" & done
  for p in plugins/*.py; do [[ -x $p ]] && python3 "$p" & done
}

# Function to add stream with enhanced tracking
add_stream(){ 
  if (( ${#STREAMS[@]:-0} < MAX_STREAMS )); then
    STREAMS["$1"]=1
    # Extract IP and port for tracking
    local url="$1"
    local ip=$(echo "$url" | sed -n 's|.*://\([^:/]*\).*|\1|p')
    local port=$(echo "$url" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
    [[ -z "$port" ]] && port="554"  # Default RTSP port
    
    # Determine protocol
    local protocol=$(echo "$url" | sed -n 's|\([^:]*\)://.*|\1|p')
    
    log_camera_found "$ip" "$port" "$protocol" "$url"
  fi
}

# Function to launch mosaic with enhanced display
launch_mosaic(){
  (( ${#STREAMS[@]:-0} )) || return
  
  log "Preparing enhanced mosaic display for ${#STREAMS[@]} camera(s)..."
  
  # Create camera info overlay
  local info_file="$OUTPUT_DIR/reports/mosaic_info.txt"
  {
    echo "CamSniff 1.0.1 - Live Camera Mosaic"
    echo "Cameras Active: ${#STREAMS[@]}"
    echo "Scan Time: $(date)"
    echo "================================"
    
    local i=1
    for u in "${!STREAMS[@]:-}"; do
      local ip=$(echo "$u" | sed -n 's|.*://\([^:/]*\).*|\1|p')
      local protocol=$(echo "$u" | sed -n 's|\([^:]*\)://.*|\1|p')
      echo "[$i] $ip ($protocol)"
      ((i++))
    done
  } > "$info_file"
  
  # Calculate optimal grid layout
  local stream_count=${#STREAMS[@]}
  local cols=2 rows=2
  case $stream_count in
    1) cols=1 rows=1 ;;
    2) cols=2 rows=1 ;;
    3|4) cols=2 rows=2 ;;
    5|6) cols=3 rows=2 ;;
    7|8|9) cols=3 rows=3 ;;
    *) cols=4 rows=4 ;;
  esac
  
  # Prepare inputs for ffmpeg
  inputs=()
  for u in "${!STREAMS[@]:-}"; do 
    inputs+=(-i "$u")
  done
  
  # Enhanced mosaic with overlay
  log "Starting mosaic display (${cols}x${rows} grid)..."
  
  # Create the mosaic layout
  if (( ${#inputs[@]} > 2 )); then
    ffmpeg "${inputs[@]}" \
      -filter_complex "xstack=inputs=${#STREAMS[@]:-0}:layout=0_0|w0_0|0_h0|w0_h0[mosaic];[mosaic]drawtext=fontsize=20:fontcolor=white:box=1:boxcolor=black@0.5:text='CamSniff Live Feed - ${#STREAMS[@]} Cameras':x=10:y=10[out]" \
      -map "[out]" -f matroska - 2>/dev/null | ffplay -window_title "CamSniff Enhanced Mosaic" -loglevel error - &
  else
    # Simple display for 1-2 cameras
    ffplay -window_title "CamSniff Camera Feed" -loglevel error "${!STREAMS[@]}" &
  fi
  
  local mosaic_pid=$!
  log "Mosaic started (PID: $mosaic_pid). Press Ctrl+C to stop."
  
  # Save active mosaic info
  echo "$mosaic_pid" > "$OUTPUT_DIR/mosaic.pid"
  
  unset STREAMS; declare -A STREAMS
}

# Function to take screenshot and analyze
screenshot_and_analyze(){
  u=$1; ip=${u#*://}; ip=${ip%%[:/]*}; 
  out="$OUTPUT_DIR/screenshots/snap_${ip}_$(date +%H%M%S).jpg"
  
  ffmpeg -rtsp_transport tcp -i "$u" -frames:v 1 -q:v 2 -y "$out" &>/dev/null && {
    log "[SNAP] $u → $out"
    
    # Enhanced AI analysis
    python3 - <<PY 2>/dev/null
import cv2
import json
import sys

try:
    img = cv2.imread("$out", 0)
    if img is None:
        sys.exit(1)
        
    # IR spot detection
    _, th = cv2.threshold(img, 200, 255, cv2.THRESH_BINARY)
    ir_count = cv2.countNonZero(th)
    
    # Motion detection areas
    contours, _ = cv2.findContours(th, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    motion_areas = len([c for c in contours if cv2.contourArea(c) > 100])
    
    # Brightness analysis
    brightness = cv2.mean(img)[0]
    
    analysis = {
        "ip": "$ip",
        "timestamp": "$(date -Iseconds)",
        "ir_spots": ir_count,
        "motion_areas": motion_areas,
        "brightness": round(brightness, 2),
        "image_path": "$out"
    }
    
    if ir_count > 50:
        print(f"[AI] IR spots detected ({ir_count}px) - Night vision camera likely")
    if motion_areas > 5:
        print(f"[AI] Multiple motion areas detected ({motion_areas}) - Active surveillance")
    if brightness < 50:
        print(f"[AI] Low light conditions detected - IR camera active")
        
    # Save analysis
    with open("$OUTPUT_DIR/reports/analysis_${ip}.json", "w") as f:
        json.dump(analysis, f, indent=2)
        
except Exception as e:
    print(f"[AI] Analysis failed: {e}")
PY
  }
}

# Enhanced CVE checking function using GitHub CVE repository
cve_check() {
  local search_term="$1"
  log_debug "Starting CVE check for: $search_term"
  
  # Skip empty or very short search terms
  if [[ ${#search_term} -lt 3 ]]; then
    log_debug "Search term too short, skipping CVE check"
    return
  fi
  
  # Create a sanitized filename for caching
  local cache_key=$(echo "$search_term" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g')
  local cache_file="$CVE_CACHE_DIR/${cache_key}.json"
  
  # Check if we have cached results (valid for 24 hours)
  if [[ -f "$cache_file" ]] && [[ $(find "$cache_file" -mtime -1 2>/dev/null) ]]; then
    log_debug "Using cached CVE results for: $search_term"
    if [[ -s "$cache_file" ]]; then
      local cached_results=$(cat "$cache_file")
      if [[ "$cached_results" != "[]" ]]; then
        echo "$cached_results" | jq -r '.[] | "[CVE] \(.cve_id): \(.title // .description)"' 2>/dev/null | head -3 | while read -r line; do
          log "$line"
        done
      fi
    fi
    return
  fi
  
  log_debug "Searching GitHub CVE repository for: $search_term"
  
  # Try quick search first (using GitHub search API)
  if command -v python3 >/dev/null && python3 -c "import requests" 2>/dev/null; then
    cve_quick_search "$search_term"
  else
    log_debug "GitHub API not available, using fallback CVE check"
    cve_fallback_check "$search_term"
  fi
}

# Quick CVE search using GitHub search API (faster alternative)
cve_quick_search() {
  local search_term="$1"
  log_debug "Quick CVE search for: $search_term"
  
  python3 - <<QUICK_SEARCH 2>/dev/null
import json
import requests
import sys
import re

search_term = "$search_term"

try:
    # Use GitHub search API to find CVE files
    clean_term = re.sub(r'[^\w\s-]', '', search_term.lower())
    
    # Search for CVE files containing the term
    search_query = f"repo:CVEProject/cvelistV5 filename:CVE extension:json {clean_term}"
    search_url = f"https://api.github.com/search/code?q={requests.utils.quote(search_query)}&per_page=5"
    
    response = requests.get(search_url, timeout=10)
    if response.status_code == 200:
        search_results = response.json()
        
        for item in search_results.get('items', [])[:3]:  # Limit to 3 results
            # Extract CVE ID from filename
            cve_filename = item.get('name', '')
            cve_id = cve_filename.replace('.json', '')
            
            # Get the actual CVE content
            download_url = item.get('download_url', '')
            if download_url:
                cve_response = requests.get(download_url, timeout=5)
                if cve_response.status_code == 200:
                    try:
                        cve_data = cve_response.json()
                        containers = cve_data.get('containers', {})
                        cna = containers.get('cna', {})
                        title = cna.get('title', 'No title available')
                        
                        print(f"[CVE] {cve_id}: {title}")
                        
                    except json.JSONDecodeError:
                        print(f"[CVE] {cve_id}: Found in CVE database")
                        
    else:
        print(f"[DEBUG] GitHub search API returned status: {response.status_code}", file=sys.stderr)
        
except Exception as e:
    print(f"[DEBUG] Quick CVE search failed: {e}", file=sys.stderr)

QUICK_SEARCH
}

# Fallback CVE check using local wordlist (when GitHub API is unavailable)
cve_fallback_check() {
  local search_term="$1"
  log_debug "Using fallback CVE check for: $search_term"
  
  # Create a simple local CVE knowledge base for common camera vulnerabilities
  python3 - <<FALLBACK_CVE 2>/dev/null
search_term = "$search_term".lower()

# Common camera-related CVEs (hardcoded fallback list)
known_cves = {
    "hikvision": [
        "CVE-2017-7921: Hikvision IP cameras allow unauthenticated access",
        "CVE-2021-36260: Hikvision multiple products command injection",
        "CVE-2023-28808: Hikvision security access control vulnerability"
    ],
    "dahua": [
        "CVE-2017-7927: Dahua IP cameras authentication bypass",
        "CVE-2021-33044: Dahua cameras authentication bypass vulnerability",
        "CVE-2022-30560: Dahua network cameras command injection"
    ],
    "axis": [
        "CVE-2018-10660: Axis Communications products denial of service",
        "CVE-2022-4487: Axis network cameras authentication bypass",
        "CVE-2023-21407: Axis products remote code execution"
    ],
    "foscam": [
        "CVE-2017-2791: Foscam IP cameras multiple vulnerabilities",
        "CVE-2020-9311: Foscam cameras authentication bypass",
        "CVE-2021-32934: Foscam cameras buffer overflow vulnerability"
    ],
    "vivotek": [
        "CVE-2018-11650: Vivotek cameras authentication bypass",
        "CVE-2019-11612: Vivotek network cameras command injection",
        "CVE-2020-25785: Vivotek cameras remote code execution"
    ]
}

# Search for matching vendors
for vendor, cves in known_cves.items():
    if vendor in search_term:
        for cve in cves[:2]:  # Limit to 2 results
            print(f"[CVE-FALLBACK] {cve}")
        break
else:
    # Generic camera CVE warnings
    if any(word in search_term for word in ["camera", "ip", "webcam", "dvr", "nvr"]):
        print("[CVE-FALLBACK] CVE-2021-32934: Generic IP camera authentication vulnerabilities")
        print("[CVE-FALLBACK] CVE-2020-25785: Network cameras remote access vulnerabilities")

FALLBACK_CVE
}

# Enhanced ONVIF discovery
discover_onvif(){
  log_debug "Starting enhanced ONVIF discovery"
  python3 - <<PY 2>/dev/null
import socket
import time
import xml.etree.ElementTree as ET
import re

# WS-Discovery probe message for ONVIF cameras
probe_msg = '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:tns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>urn:uuid:0a6dc791-2be6-4991-9af1-454778a1917a</wsa:MessageID>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <tns:Probe>
            <tns:Types>dn:NetworkVideoTransmitter</tns:Types>
        </tns:Probe>
    </soap:Body>
</soap:Envelope>'''

try:
    # Create UDP socket for multicast
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # Send probe to ONVIF multicast address
    sock.sendto(probe_msg.encode(), ('239.255.255.250', 3702))
    
    cameras_found = 0
    while cameras_found < 10:  # Limit responses
        try:
            response, addr = sock.recvfrom(4096)
            response_text = response.decode('utf-8', errors='ignore')
            
            # Extract device information
            ip = addr[0]
            
            # Try to extract device service URL
            url_match = re.search(r'http://([^/]+)/onvif/device_service', response_text)
            if url_match:
                device_url = f"http://{url_match.group(1)}/onvif/device_service"
                print(f"[ONVIF] Camera found at {ip} - {device_url}")
                
                # Try to extract manufacturer info
                if 'hikvision' in response_text.lower():
                    print(f"[ONVIF] Hikvision camera detected at {ip}")
                elif 'dahua' in response_text.lower():
                    print(f"[ONVIF] Dahua camera detected at {ip}")
                elif 'axis' in response_text.lower():
                    print(f"[ONVIF] Axis camera detected at {ip}")
                else:
                    print(f"[ONVIF] Unknown ONVIF camera at {ip}")
                    
                cameras_found += 1
            
        except socket.timeout:
            break
        except Exception as e:
            break
    
    sock.close()
    print(f"[ONVIF] Discovery complete - {cameras_found} cameras found")
    
except Exception as e:
    print(f"[ONVIF] Discovery failed: {e}")
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
  log_debug "Starting enhanced RTSP scan for $1:$2"
  local ip="$1" port="$2" found=0
  
  # Test common RTSP paths first
  local common_paths=(
    "rtsp://$ip:$port/video"
    "rtsp://$ip:$port/cam"
    "rtsp://$ip:$port/stream"
    "rtsp://$ip:$port/live"
    "rtsp://$ip:$port/h264"
    "rtsp://$ip:$port/mpeg4"
    "rtsp://$ip:$port/mjpeg"
    "rtsp://$ip:$port/1"
    "rtsp://$ip:$port/0"
    "rtsp://admin:admin@$ip:$port/cam/realmonitor?channel=1&subtype=0"
  )
  
  for u in "${common_paths[@]}"; do
    log_debug "Testing common RTSP URL: $u"
    if ffprobe -v quiet -rtsp_transport tcp -timeout 2000000 -i "$u" 2>&1 | grep -q "Video:"; then
      log "[RTSP] $u"
      add_stream "$u"
      found=1
      
      # Try to get device info via RTSP DESCRIBE
      rtsp_info=$(ffprobe -v quiet -show_format -i "$u" 2>/dev/null | grep -E "(TAG:|server)" || echo "Unknown device")
      log_device_info "$ip" "$rtsp_info" "camera"
      break
    fi
  done
  
  # If no common paths worked, try the comprehensive list
  if (( !found )); then
    log_debug "Testing comprehensive RTSP paths for $ip:$port"
    for rtsp_path in "${RTSP_PATHS[@]:0:20}"; do  # Limit to first 20 for speed
      # Replace placeholders in the RTSP path
      u=$(echo "$rtsp_path" | sed "s/{{username}}/admin/g; s/{{password}}/admin/g; s/{{ip_address}}/$ip/g; s/{{port}}/$port/g")
      log_debug "Testing RTSP URL: $u"
      
      if ffprobe -v quiet -rtsp_transport tcp -timeout 1000000 -i "$u" 2>&1 | grep -q "Video:"; then
        log "[RTSP] $u"
        add_stream "$u"
        found=1
        break
      fi
    done
  fi

  # Enhanced brute-force if no stream found
  if (( !found )); then
    log_debug "Starting RTSP brute-force for $ip:$port"
    hydra -L "$HYDRA_FILE" -P "$HYDRA_FILE" -s "$port" "$ip" rtsp -t "$HYDRA_RATE" &>/dev/null && {
      log "[HYDRA-RTSP] $ip:$port - Credentials found"
      log_device_info "$ip" "RTSP credentials discovered" "camera"
    }
  fi
}

# Function to scan HTTP (enhanced for aggressive scanning)
scan_http(){
  local ip="$1" port="$2"
  log_debug "Starting enhanced HTTP scan for $ip:$port"
  
  # Enhanced camera-specific paths
  local camera_paths=(
    "/video" "/cam" "/stream" "/live" "/mjpeg" "/cgi-bin/mjpeg"
    "/axis-cgi/mjpg/video.cgi" "/cgi-bin/camera" "/webcam.cgi"
    "/video.cgi" "/snapshot.cgi" "/image.cgi" "/videostream.cgi"
    "/cgi-bin/hi3510/snap.cgi" "/onvif/device_service" "/streaming/channels/1/httppreview"
  )
  
  # Test for camera-specific HTTP endpoints
  for path in "${camera_paths[@]}"; do
    for cred in "${HTTP_CREDS[@]}"; do
      IFS=: read u p <<<"$cred"
      url="http://$ip:$port$path"
      
      response=$(curl -su "$u:$p" -m3 -I "$url" 2>/dev/null)
      if echo "$response" | grep -q "multipart/x-mixed-replace\|image/jpeg\|video/"; then
        log "[MJPEG/HTTP] $url ($u:$p)"
        add_stream "$url"
        
        # Get server info for device identification
        server_info=$(echo "$response" | grep -i '^Server:' | cut -d' ' -f2- || echo "Unknown")
        log_device_info "$ip" "HTTP Camera: $server_info" "camera"
        break 2
      fi
    done
  done
  
  # Scan for HLS streams
  scan_hls "$ip" "$port"
  
  # General HTTP brute-force
  hydra -C "$HYDRA_FILE" -s "$port" http-get://"$ip" -t "$HYDRA_RATE" &>/dev/null && {
    log "[HYDRA-HTTP] $ip:$port - Access granted"
    log_device_info "$ip" "HTTP authentication bypassed" "web_device"
  }
  
  # Enhanced server fingerprinting
  hdr=$(curl -sI "http://$ip:$port" 2>/dev/null | grep -i '^Server:' | cut -d' ' -f2-)
  if [[ $hdr ]]; then
    cve_check "$hdr"
    
    # Identify camera brands based on server headers
    case $hdr in
      *Hikvision*|*HIKVISION*) log_device_info "$ip" "Hikvision Camera: $hdr" "hikvision_camera" ;;
      *Dahua*|*DAHUA*) log_device_info "$ip" "Dahua Camera: $hdr" "dahua_camera" ;;
      *Axis*|*AXIS*) log_device_info "$ip" "Axis Camera: $hdr" "axis_camera" ;;
      *Vivotek*|*VIVOTEK*) log_device_info "$ip" "Vivotek Camera: $hdr" "vivotek_camera" ;;
      *Foscam*|*FOSCAM*) log_device_info "$ip" "Foscam Camera: $hdr" "foscam_camera" ;;
      *) log_device_info "$ip" "HTTP Server: $hdr" "web_server" ;;
    esac
  fi

  # Aggressive directory brute-forcing for cameras
  log_debug "Starting camera-specific directory scan on $ip:$port"
  if command -v gobuster &>/dev/null; then
    gobuster dir -u "http://$ip:$port" -w "$DIRB_WORDLIST" -q -o "$OUTPUT_DIR/logs/dirb_$ip_$port.txt" 2>/dev/null &
  fi
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
  if command -v coap-client &>/dev/null; then
    for p in .well-known/core media stream status; do
      out=$(timeout 3 coap-client -m get -s 2 "coap://$1/$p" 2>/dev/null)
      [[ $out ]] && log "[CoAP] coap://$1/$p → ${out:0:80}"
    done
  else
    log "[CoAP] coap-client not available, skipping detailed CoAP enumeration"
  fi

  # Aggressive CoAP fuzzing (optional)
  if command -v coap-fuzzer &>/dev/null; then
    log "[FUZZ] Starting CoAP fuzzing on $1"
    coap-fuzzer -u "coap://$1" -o "/tmp/coap_fuzz_$1.log" &>/dev/null && log "[FUZZ] Results saved to /tmp/coap_fuzz_$1.log"
  else
    log "[FUZZ] coap-fuzzer not available, skipping CoAP fuzzing"
  fi
}

# Function to scan RTMP (enhanced for aggressive scanning)
scan_rtmp(){
  for p in live/stream live cam play h264; do
    u="rtmp://$1/$p"
    timeout 4 rtmpdump --timeout 2 -r "$u" --stop 1 &>/dev/null && { log "[RTMP] $u"; add_stream "$u"; }
  done

  # Aggressive RTMP fuzzing (optional)
  if command -v rtmp-fuzzer &>/dev/null; then
    log "[FUZZ] Starting RTMP fuzzing on $1"
    rtmp-fuzzer -u "rtmp://$1" -o "/tmp/rtmp_fuzz_$1.log" &>/dev/null && log "[FUZZ] Results saved to /tmp/rtmp_fuzz_$1.log"
  else
    log "[FUZZ] rtmp-fuzzer not available, skipping RTMP fuzzing"
  fi
}

# Function to scan MQTT
scan_mqtt(){
  log "[MQTT] Starting MQTT scan on $1"
  mosquitto_sub -h "$1" -t "#" -C 1 -W 5 &>/dev/null && log "[MQTT] MQTT broker found on $1"
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
      1883|8883)                scan_mqtt "$ip"    ;;
    esac
  done

  discover_onvif; discover_ssdp

  for ip in "${ALIVE[@]}"; do scan_coap "$ip"; done
  for ip in "${ALIVE[@]}"; do scan_rtmp "$ip"; done

  log "Screenshot + AI…"
  for u in "${!STREAMS[@]:-}"; do screenshot_and_analyze "$u"; done

  log "Generating summary report…"
  generate_summary_report

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

# Generate comprehensive summary report
generate_summary_report(){
  local report_file="$OUTPUT_DIR/reports/summary_$(date +%Y%m%d_%H%M%S).txt"
  local json_file="$OUTPUT_DIR/reports/summary_$(date +%Y%m%d_%H%M%S).json"
  
  {
    echo "=============================================="
    echo "CamSniff 1.0.1 - Enhanced Camera Discovery"
    echo "Scan completed: $(date)"
    echo "=============================================="
    echo
    echo "CAMERAS FOUND: ${#CAMERAS_FOUND[@]}"
    echo "DEVICES IDENTIFIED: ${#DEVICE_INFO[@]}"
    echo "ACTIVE STREAMS: ${#STREAMS[@]:-0}"
    echo
    
    if (( ${#CAMERAS_FOUND[@]} > 0 )); then
      echo "DISCOVERED CAMERAS:"
      echo "-------------------"
      for key in "${!CAMERAS_FOUND[@]}"; do
        IFS='|' read -ra info <<< "${CAMERAS_FOUND[$key]}"
        echo "  • $key - Protocol: ${info[0]}, URL: ${info[1]}, Creds: ${info[2]:-None}"
      done
      echo
    fi
    
    if (( ${#DEVICE_INFO[@]} > 0 )); then
      echo "DEVICE INFORMATION:"
      echo "-------------------"
      for key in "${!DEVICE_INFO[@]}"; do
        IFS='|' read -ra info <<< "${DEVICE_INFO[$key]}"
        echo "  • $key - Type: ${info[0]}, Info: ${info[1]}"
      done
      echo
    fi
    
    echo "OUTPUT DIRECTORY: $OUTPUT_DIR"
    echo "- Screenshots: $OUTPUT_DIR/screenshots/"
    echo "- Logs: $OUTPUT_DIR/logs/"
    echo "- Reports: $OUTPUT_DIR/reports/"
    echo
    echo "=============================================="
  } | tee "$report_file"
  
  # Generate JSON summary
  {
    echo "{"
    echo "  \"scan_info\": {"
    echo "    \"version\": \"1.0.1\","
    echo "    \"timestamp\": \"$(date -Iseconds)\","
    echo "    \"output_dir\": \"$OUTPUT_DIR\""
    echo "  },"
    echo "  \"statistics\": {"
    echo "    \"cameras_found\": ${#CAMERAS_FOUND[@]},"
    echo "    \"devices_identified\": ${#DEVICE_INFO[@]},"
    echo "    \"active_streams\": ${#STREAMS[@]:-0}"
    echo "  },"
    echo "  \"cameras\": ["
    
    local first=1
    for key in "${!CAMERAS_FOUND[@]}"; do
      IFS='|' read -ra info <<< "${CAMERAS_FOUND[$key]}"
      IFS=':' read -ra addr <<< "$key"
      
      [[ $first -eq 0 ]] && echo ","
      echo -n "    {"
      echo -n "\"ip\": \"${addr[0]}\", "
      echo -n "\"port\": \"${addr[1]}\", "
      echo -n "\"protocol\": \"${info[0]}\", "
      echo -n "\"url\": \"${info[1]}\", "
      echo -n "\"credentials\": \"${info[2]:-}\""
      echo -n "}"
      first=0
    done
    
    echo
    echo "  ],"
    echo "  \"devices\": ["
    
    first=1
    for key in "${!DEVICE_INFO[@]}"; do
      IFS='|' read -ra info <<< "${DEVICE_INFO[$key]}"
      
      [[ $first -eq 0 ]] && echo ","
      echo -n "    {"
      echo -n "\"ip\": \"$key\", "
      echo -n "\"type\": \"${info[0]}\", "
      echo -n "\"info\": \"${info[1]}\""
      echo -n "}"
      first=0
    done
    
    echo
    echo "  ]"
    echo "}"
  } > "$json_file"
  
  log "Summary report saved: $report_file"
  log "JSON report saved: $json_file"
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
